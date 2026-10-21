#include "ui/main_window.h"
#include "ui/tcp_dialog.h"
#include "ui/stream_pane.h"
#include "fixtures.h"
#include "core/pcap_file.h"
#include "version.h"
#include <QApplication>
#include <QCheckBox>
#include <QAction>
#include <QComboBox>
#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPushButton>
#include <QTemporaryDir>
#include <QStyleFactory>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <future>
#include <QFontDatabase>
#include <thread>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#endif

namespace {
using namespace etherscope;
constexpr std::int64_t timestampBase=1700000000000000000LL;
std::uint64_t resident() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX memory{};memory.cb=sizeof(memory);
    if(GetProcessMemoryInfo(GetCurrentProcess(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),sizeof(memory)))return memory.PrivateUsage;
#endif
    return 0;
}
double cpuSeconds() {
#ifdef _WIN32
    FILETIME created,exited,kernel,user;
    if(GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)) {
        const auto ticks=[](FILETIME value){return (std::uint64_t(value.dwHighDateTime)<<32)|value.dwLowDateTime;};
        return double(ticks(kernel)+ticks(user))/10000000.0;
    }
#endif
    return 0;
}
qint64 percentile(std::vector<qint64> values,int percent) {
    if(values.empty())return 0;
    std::sort(values.begin(),values.end());return values[std::min(values.size()-1,values.size()*percent/100)];
}
}
int main(int argc,char** argv) {
    using namespace etherscope;
    QApplication app(argc,argv);app.setApplicationVersion(ETHERSCOPE_VERSION);app.setStyle(QStyleFactory::create("Fusion"));
    app.setFont(QFont("Microsoft YaHei UI",10));
    if(QGuiApplication::platformName()=="offscreen") {
        const auto fonts=qEnvironmentVariable("WINDIR")+"/Fonts/";
        QFontDatabase::addApplicationFont(fonts+"msyh.ttc");QFontDatabase::addApplicationFont(fonts+"consola.ttf");QFontDatabase::addApplicationFont(fonts+"segoeui.ttf");
    }
    int seconds=600,pps=1000;QString output="ui-benchmark.json";
    const auto args=app.arguments();
    for(int i=1;i+1<args.size();++i) {
        if(args[i]=="--seconds")seconds=args[++i].toInt();
        else if(args[i]=="--pps")pps=args[++i].toInt();
        else if(args[i]=="--output")output=args[++i];
    }
    if(seconds<2 || seconds>7200 || pps<1 || pps>100000)return 2;
    auto raws=fixtures::samples();const auto ipv6=fixtures::ipv6Samples();raws.insert(raws.end(),ipv6.begin(),ipv6.end());
    const auto analysis=fixtures::analysisSamples();raws.insert(raws.end(),analysis.begin(),analysis.end());
    if(args.contains("--tcp"))raws=fixtures::tcpConversationSamples();
    const bool streamLoad=args.contains("--stream-load");
    if(streamLoad)raws={fixtures::tcp(24,100,0,false,50000,false,std::vector<std::uint8_t>(1024,'x'))};
    for(auto& raw:raws) {raw.bytes.resize(std::max<std::size_t>(64,raw.bytes.size()),0);raw.originalLength=static_cast<std::uint32_t>(raw.bytes.size());}
    const auto target=std::uint64_t(seconds)*pps;
    auto rawAt=[&](std::uint64_t index){auto raw=raws[index%raws.size()];raw.timestampNs=timestampBase+static_cast<std::int64_t>(index)*1000000;if(streamLoad){const auto sequence=static_cast<std::uint32_t>(index*1024+100);for(unsigned i=0;i<4;++i)raw.bytes[38+i]=static_cast<std::uint8_t>(sequence>>(24-8*i));}return raw;};
    MainWindowOptions options;QTemporaryDir temporary;options.settingsFile=temporary.filePath("settings.ini");
    options.capture.interfaces=[](QString& error){error.clear();return std::vector<CaptureInterface>{{"benchmark","性能测试","192.0.2.1"}};};
    options.capture.run=[&](const QString&,bool,std::stop_token stop,const CaptureHooks::Sink& sink,const CaptureHooks::Opened& opened,const LiveCaptureOptions&){
        opened("捕获中");const auto start=std::chrono::steady_clock::now();
        std::uint64_t sent=0;
        while(!stop.stop_requested()) {
            const auto elapsed=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count();
            const auto due=std::min(target,std::uint64_t(elapsed)*pps/1000000);
            while(sent<due && !stop.stop_requested()) {
                auto raw=rawAt(sent);
                sink(std::move(raw));++sent;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    };
    struct ExpectedExport {std::uint64_t count;std::int64_t first,last;};std::deque<ExpectedExport> expectedExports;
    options.snapshotObserver=[&](const PacketSnapshot& snapshot){expectedExports.push_back({snapshot.size(),snapshot.front()->raw.timestampNs,snapshot.back()->raw.timestampNs});};
    std::vector<std::size_t> footprints;for(auto raw:raws)footprints.push_back(decodeSummary(std::move(raw)).estimatedBytes);
    std::size_t expectedRetained=0,expectedRaw=0,expectedBytes=0;
    for(auto id=target;id>0 && expectedRetained<10000;--id){const auto index=static_cast<std::size_t>((id-1)%raws.size()),rawBytes=raws[index].bytes.size(),cost=footprints[index];
        if(expectedRaw+rawBytes>64*1024*1024 || expectedBytes+cost>64*1024*1024)break;++expectedRetained;expectedRaw+=rawBytes;expectedBytes+=cost;}
    MainWindow window(nullptr,options);window.resize(1280,820);window.show();
    if(args.contains("--tcp-panel") || streamLoad)window.findChild<QAction*>("tcpConversationsAction")->trigger();
    StreamPane* streamPane=nullptr;int streamRequests=0,streamCompleted=0;bool streamValid=true;qint64 nextStream=2000;
    if(streamLoad){streamPane=window.findChild<StreamPane*>();QObject::connect(streamPane,&StreamPane::analysisFinished,&app,[&](quint64,bool success){streamValid=streamValid && success;++streamCompleted;});}
    QElapsedTimer clock,stopClock;clock.start();const auto cpuStart=cpuSeconds();
    std::vector<qint64> delays,appendTimes,filterTimes;QJsonArray memorySamples;QJsonArray exports;QJsonArray stalls;
    QTimer poll;poll.setTimerType(Qt::PreciseTimer);qint64 lastBeat=0,lastMemory=-1000,nextProgress=60000;
    bool stopping=false,selected=false,theme=false,filtered=false,cleared=false,intentionalReset=false;
    int resets=0,saveRequests=0;bool saveValid=true;
    qint64 themeUs=0;std::vector<std::future<QJsonObject>> validations;
    QObject::connect(window.packetModel(),&QAbstractItemModel::modelReset,&app,[&]{if(!intentionalReset && window.captureState()!=MainWindow::CaptureState::Starting)++resets;});
    QObject::connect(&window,&MainWindow::batchProcessed,&app,[&](qint64 us){appendTimes.push_back(us);});
    QObject::connect(&window,&MainWindow::saveFinished,&app,[&](bool success,const QString& path,quint64 count,const QString& error){
        if(expectedExports.empty()){saveValid=false;return;}const auto expected=expectedExports.front();expectedExports.pop_front();
        validations.push_back(std::async(std::launch::async,[&,success,path,count,error,expected]{
        QElapsedTimer validation;validation.start();
        std::uint64_t records=0;std::int64_t previous=-1;bool exact=success && count==expected.count;
        try {
            PcapReader reader(std::filesystem::path(path.toStdWString()));
            while(auto raw=reader.next()) {
                const auto sequence=(raw->timestampNs-timestampBase)/1000000;
                exact=exact && sequence>=0 && (previous<0 || sequence==previous+1) && raw->timestampNs==timestampBase+sequence*1000000
                    && raw->bytes==rawAt(static_cast<std::uint64_t>(sequence)).bytes;
                if(records==0)exact=exact && raw->timestampNs==expected.first;previous=sequence;++records;
            }
        } catch(const std::exception&) {exact=false;}
        exact=exact && records==expected.count && timestampBase+previous*1000000==expected.last;
        return QJsonObject{{"success",success},{"exact_bytes_and_order",exact},{"count",double(count)},{"error",error},{"validation_us",double(validation.nsecsElapsed()/1000)}};
        }));
    });
    auto applyProtocol=[&](const QString& value){
        intentionalReset=true;QElapsedTimer timer;timer.start();
        window.findChild<QComboBox*>("protocolFilter")->setCurrentText(value);
        filterTimes.push_back(timer.nsecsElapsed()/1000);intentionalReset=false;
    };
    QObject::connect(&poll,&QTimer::timeout,&app,[&]{
        const auto now=clock.elapsed();
        if(lastBeat) {
            const auto delay=std::max<qint64>(0,now-lastBeat-20);delays.push_back(delay);
            if(delay>50)stalls.append(QJsonObject{{"elapsed_ms",double(now)},{"delay_ms",double(delay)}});
        }
        lastBeat=now;
        for(auto it=validations.begin();it!=validations.end();) {
            if(it->wait_for(std::chrono::seconds(0))==std::future_status::ready) {
                auto result=it->get();saveValid=saveValid && result["exact_bytes_and_order"].toBool();exports.append(result);it=validations.erase(it);
            } else ++it;
        }
        const auto c=window.captureCounters();
        if(streamLoad && now>=nextStream && now<seconds*1000 && c.enqueued>0 && !window.tcpConversations().items().empty()) {
            auto* dialog=window.findChild<TcpDialog*>();dialog->selectConversation(window.tcpConversations().items().back().id);dialog->findChild<QPushButton*>("tcpStreamButton")->click();++streamRequests;nextStream=now+2000;
        }
        if(now>=nextProgress) {
            std::cout<<"elapsed_s="<<now/1000<<" received="<<c.received<<" queue_dropped="<<c.queueDropped
                     <<" heartbeat_max_ms="<<(delays.empty()?0:*std::max_element(delays.begin(),delays.end()))<<std::endl;
            nextProgress+=60000;
        }
        if(now-lastMemory>=(seconds>=7200?5000:1000)) {lastMemory=now;memorySamples.append(QJsonObject{{"elapsed_ms",double(now)},{"private_bytes",double(resident())}});}
        if(!selected && c.enqueued>=2000) {window.selectPacket(0);selected=true;}
        if(!theme && c.enqueued>=5000) {QElapsedTimer themeTimer;themeTimer.start();window.setDarkTheme(false);themeUs=themeTimer.nsecsElapsed()/1000;theme=true;}
        if(!filtered && now>=seconds*200) {applyProtocol("ICMP");intentionalReset=true;window.findChild<QComboBox*>("icmpTypeFilter")->setCurrentIndex(3);intentionalReset=false;filtered=true;}
        if(!cleared && now>=seconds*450) {applyProtocol("全部协议");cleared=true;}
        const bool saveDue=(saveRequests==0 && now>=std::max(11000,seconds*300)) || (saveRequests==1 && now>=std::max(13000,seconds*650));
        if(saveDue && !window.saving()) {
            if(window.saveFile(temporary.filePath(QString("capture-%1.pcap").arg(saveRequests))))++saveRequests;
            else saveValid=false;
        }
        if(!stopping && now>=seconds*1000 && c.enqueued>=target) {stopping=true;stopClock.start();window.stopCapture();}
        if(stopping && !window.busy() && !window.saving() && validations.empty() && (!streamPane || !streamPane->busy())) {
            poll.stop();const auto stopMs=stopClock.elapsed();const auto final=window.captureCounters();
            double warm=0,tail=0;int wn=0,tn=0;std::uint64_t peak=0;
            const auto warmBegin=std::min(60000,seconds*250),warmEnd=std::min(120000,seconds*500);
            for(const auto& value:memorySamples) {
                const auto sample=value.toObject();const auto t=sample["elapsed_ms"].toDouble(),bytes=sample["private_bytes"].toDouble();
                peak=std::max(peak,static_cast<std::uint64_t>(bytes));
                if(t>=warmBegin && t<warmEnd){warm+=bytes;++wn;}
                if(t>=seconds*1000-std::min(60000,seconds*200)){tail+=bytes;++tn;}
            }
            const double growth=wn && tn?tail/tn-warm/wn:0;
            std::vector<qint64> warmMemory,tailMemory;
            for(const auto& sample:memorySamples) {
                const auto v=sample.toObject();const auto t=v["elapsed_ms"].toDouble();const auto bytes=static_cast<qint64>(v["private_bytes"].toDouble());
                if(t>=900000 && t<1500000)warmMemory.push_back(bytes);
                if(t>=seconds*1000-600000)tailMemory.push_back(bytes);
            }
            const auto medianGrowth=seconds>=7200?percentile(tailMemory,50)-percentile(warmMemory,50):0;
            const auto maximum=delays.empty()?0:*std::max_element(delays.begin(),delays.end());
            const auto p99=percentile(delays,99),appendP99=percentile(appendTimes,99),filterMax=filterTimes.empty()?0:*std::max_element(filterTimes.begin(),filterTimes.end());
            const bool counts=final.received==target && window.sessionStats().received+final.queueDropped==final.received && final.queuedPackets==0;
            const bool passed=counts && final.queueDropped==0 && (seconds>=7200 || (p99<=10 && maximum<=250 && appendP99<=8000 && filterMax<=100000))
                && stopMs<=1000 && peak<=256*1024*1024 && (seconds>=7200?(!warmMemory.empty() && !tailMemory.empty() && medianGrowth<=8*1024*1024):growth<=16*1024*1024) && window.packetModel()->rowCount()==static_cast<int>(expectedRetained)
                && window.retainedRawBytes()==expectedRaw && window.retainedEstimatedBytes()<=64*1024*1024 && resets==0 && saveRequests==2 && exports.size()==2 && saveValid && streamValid && (!streamLoad || streamCompleted==streamRequests);
            QJsonObject report{{"kind","synthetic_source_capture_decode_queue_store_ui"},{"version",ETHERSCOPE_VERSION},
                {"tcp_fixture",args.contains("--tcp")},{"tcp_panel",args.contains("--tcp-panel")},
                {"stream_load",streamLoad},{"stream_requests",streamRequests},{"stream_completed",streamCompleted},
                {"tcp_connections",double(window.tcpConversations().items().size())},{"tcp_estimated_bytes",double(window.tcpConversations().estimatedBytes())},
                {"tcp_overwritten",double(window.tcpConversations().overwritten())},{"tcp_skipped",double(window.tcpConversations().skipped())},
                {"utc",QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},{"requested_seconds",seconds},{"target_pps",pps},
                {"elapsed_ms",double(now)},{"received",double(final.received)},{"parsed",double(window.sessionStats().received)},
                {"achieved_pps",final.received*1000.0/now},{"queue_dropped",double(final.queueDropped)},
                {"queue_peak_packets",double(final.peakQueuedPackets)},{"queue_peak_raw_bytes",double(final.peakQueuedBytes)},
                {"retained_rows",window.packetModel()->rowCount()},{"expected_retained_rows",double(expectedRetained)},{"retained_estimated_bytes",double(window.retainedEstimatedBytes())},{"retained_raw_bytes",double(window.retainedRawBytes())},
                {"heartbeat_p99_delay_ms",double(p99)},{"heartbeat_max_delay_ms",double(maximum)},
                {"theme_change_us",double(themeUs)},{"batch_p99_us",double(appendP99)},{"batch_max_us",double(appendTimes.empty()?0:*std::max_element(appendTimes.begin(),appendTimes.end()))},{"heartbeat_stalls",stalls},{"filter_max_us",double(filterMax)},{"model_resets_during_feed",resets},
                {"stop_completed_ms",double(stopMs)},{"peak_private_bytes",double(peak)},{"tail_growth_bytes",growth},{"warm_tail_median_growth_bytes",double(medianGrowth)},
                {"cpu_single_core_average_percent",(cpuSeconds()-cpuStart)*100000.0/now},
                {"exports",exports},{"memory_samples",memorySamples},{"counts_reconciled",counts},{"passed",passed}};
            QFile file(output);if(!file.open(QIODevice::WriteOnly)){app.exit(3);return;}file.write(QJsonDocument(report).toJson());
            std::cout<<"packets="<<final.received<<" p99_ms="<<p99<<" stop_ms="<<stopMs<<" passed="<<passed<<"\n";app.exit(passed?0:1);
        }
        if(now>seconds*1000+15000)app.exit(4);
    });
    QObject::connect(&window,&MainWindow::interfacesFinished,&app,[&]{intentionalReset=true;window.findChild<QPushButton*>("startButton")->click();intentionalReset=false;});poll.start(20);return app.exec();
}
