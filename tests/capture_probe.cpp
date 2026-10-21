#include "capture/capture.h"
#include "core/pcap_file.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QElapsedTimer>
#include <QDateTime>
#include <algorithm>
#include <fstream>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

using namespace etherscope;
int main(int argc,char** argv) {
    QCoreApplication app(argc,argv);const auto args=app.arguments();QString device,output,marker,target,pcap,ready;int duration=5000;
    for(int i=1;i<args.size();++i) {
        if(i+1>=args.size())break;
        if(args[i]=="--device")device=args[++i];else if(args[i]=="--output")output=args[++i];else if(args[i]=="--marker")marker=args[++i];
        else if(args[i]=="--target")target=args[++i];else if(args[i]=="--pcap")pcap=args[++i];else if(args[i]=="--ready-file")ready=args[++i];
        else if(args[i]=="--duration-ms")duration=args[++i].toInt();
    }
    if(duration<1000 || duration>30000 || (!marker.isEmpty() && (target.isEmpty() || pcap.isEmpty())))return 2;
    CaptureHooks hooks;hooks.disableDataEvent=args.contains("--wait-fallback");CaptureEngine engine(nullptr,hooks);QString error;const auto devices=engine.interfaces(error);
    auto cpuSeconds=[]{
#ifdef _WIN32
        FILETIME created,ended,kernel,user;GetProcessTimes(GetCurrentProcess(),&created,&ended,&kernel,&user);
        auto value=[](FILETIME t){return (std::uint64_t(t.dwHighDateTime)<<32)|t.dwLowDateTime;};return double(value(kernel)+value(user))/10000000.0;
#else
        return 0.0;
#endif
    };const auto cpuStart=cpuSeconds();
    bool opened=false,stopping=false;std::uint64_t decoded=0;QElapsedTimer stop,openedClock; qint64 firstBatchMs=-1;std::vector<Packet> matches;QJsonArray observations;QJsonObject protocols;int requests=0,replies=0;
    const auto payload=marker.toUtf8();
    const bool ipv6=target.contains(':');
    if(device.isEmpty()) for(const auto& candidate:devices) if(!candidate.addresses.isEmpty()) {device=candidate.name;break;}
    auto take=[&]{
        auto batch=engine.takeBatch();if(!batch.empty() && firstBatchMs<0 && openedClock.isValid())firstBatchMs=openedClock.elapsed();decoded+=batch.size();for(const auto& packet:batch){const auto name=QString::fromStdString(packet.protocol);protocols[name]=protocols.value(name).toInt()+1;}if(marker.isEmpty())return;
        for(auto& packet:batch) {
            if(packet.protocol!=(ipv6?"ICMPv6":"ICMP") || (packet.source!=target.toStdString() && packet.destination!=target.toStdString()))continue;
            const auto details=decodeDetails(packet.raw);
            const auto group=std::find_if(details.fields.begin(),details.fields.end(),[&](const Field& f){return f.name==(ipv6?"ICMPv6":"ICMP");});
            if(group==details.fields.end() || group->length!=static_cast<std::size_t>(payload.size())+8)continue;
            const auto offset=group->offset;const auto& bytes=packet.raw.bytes;
            const auto requestType=ipv6?128:8,replyType=ipv6?129:0;
            if(offset+group->length>bytes.size() || bytes[offset+1]!=0 || (bytes[offset]!=replyType && bytes[offset]!=requestType))continue;
            if(!std::equal(payload.begin(),payload.end(),bytes.begin()+offset+8,[](char a,std::uint8_t b){return static_cast<std::uint8_t>(a)==b;}))continue;
            if(bytes[offset]==requestType)++requests;else ++replies;
            observations.append(QJsonObject{{"type",bytes[offset]},{"source",QString::fromStdString(packet.source)},{"destination",QString::fromStdString(packet.destination)},
                {"identifier",(bytes[offset+4]<<8)|bytes[offset+5]},{"sequence",(bytes[offset+6]<<8)|bytes[offset+7]},{"captured_bytes",static_cast<int>(bytes.size())}});
            matches.push_back(std::move(packet));
        }
    };
    QTimer drain;QObject::connect(&drain,&QTimer::timeout,&app,take);drain.start(100);
    QObject::connect(&engine,&CaptureEngine::opened,&app,[&](quint64,const QString&){opened=true;openedClock.start();if(!ready.isEmpty()){QFile flag(ready);if(flag.open(QIODevice::WriteOnly))flag.write("ready");}});
    QObject::connect(&engine,&CaptureEngine::failed,&app,[&](quint64,const QString& message){error=message;});
    auto finish=[&]{
        drain.stop();take();const auto count=engine.counters();const auto stopMs=stopping?stop.elapsed():-1;
        if(!pcap.isEmpty())try {std::vector<const Packet*> refs;for(const auto& packet:matches)refs.push_back(&packet);std::ofstream file(std::filesystem::path(pcap.toStdWString()),std::ios::binary);writePcap(file,refs);}catch(const std::exception& e){error=QString::fromUtf8(e.what());}
        const bool allowEmpty=args.contains("--allow-empty");
        const bool passed=error.isEmpty() && opened && (allowEmpty || count.received>0) && decoded==count.received && count.queueDropped==0 && (marker.isEmpty() || (requests>0 && replies>0));
        QJsonObject report{{"kind",allowEmpty?"npcap_idle_receive_wait":(marker.isEmpty()?"same_machine_npcap_short_capture_no_packet_bytes_saved":"controlled_icmp_real_capture_unique_payload")},{"utc",QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
            {"enumerated_interfaces",static_cast<int>(devices.size())},{"opened",opened},{"received",double(count.received)},{"decoded",double(decoded)},
            {"protocols",protocols},{"bpf",args.contains("--bpf")?args.value(args.indexOf("--bpf")+1):QString{}},{"queue_dropped",double(count.queueDropped)},{"stop_completed_ms",double(stopMs)},{"first_batch_ms",double(firstBatchMs)},{"duration_ms",duration},{"error",error},{"passed",passed},
            {"wait_strategy",count.waitStrategy},{"wait_wakeups",double(count.waitWakeups)},{"cpu_single_core_average_percent",(cpuSeconds()-cpuStart)*100000.0/duration},
            {"limits","One local adapter and ICMP echo scenario only; not all ICMP types, long throughput, or second-machine acceptance."}};
        if(!marker.isEmpty()){report["ip_version"]=ipv6?6:4;report["marker"]=marker;report["target"]=target;report["echo_requests"]=requests;report["echo_replies"]=replies;report["matched_packets"]=observations;report["pcap_contains_only_matching_test_packets"]=true;}
        if(count.driverDropped)report["driver_dropped"]=double(*count.driverDropped);else report["driver_dropped"]=QJsonValue::Null;
        QFile file(output);if(!file.open(QIODevice::WriteOnly)){app.exit(3);return;}file.write(QJsonDocument(report).toJson());app.exit(passed?0:1);
    };
    QObject::connect(&engine,&CaptureEngine::finished,&app,[&](quint64){finish();});
    if(device.isEmpty()) {error=error.isEmpty()?"No IPv4 interface available":error;finish();return 2;}
    engine.startLive(device,{args.contains("--bpf")?args.value(args.indexOf("--bpf")+1):QString{}});
    QTimer::singleShot(duration,&app,[&]{stopping=true;stop.start();engine.requestStop();});
    QTimer::singleShot(duration+5000,&app,[&]{if(engine.running()){engine.requestStop();app.exit(4);}});
    return app.exec();
}
