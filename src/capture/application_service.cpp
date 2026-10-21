#include "capture/application_service.h"
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <algorithm>
#include <set>

namespace etherscope {
ApplicationAnalysisService::ApplicationAnalysisService(QObject* parent,ApplicationHooks hooks):QObject(parent),hooks_(std::move(hooks)),thread_([this](std::stop_token stop){run(stop);}){}
ApplicationAnalysisService::~ApplicationAnalysisService(){requestStop();if(thread_.joinable())thread_.join();}
std::uint64_t ApplicationAnalysisService::generation() const {std::lock_guard lock(mutex_);return generation_;}
bool ApplicationAnalysisService::busy() const {std::lock_guard lock(mutex_);return working_ || !pending_.empty();}
std::uint64_t ApplicationAnalysisService::reset() {
    std::stop_source active;std::uint64_t result;
    {std::lock_guard lock(mutex_);result=++generation_;pending_.clear();completed_.clear();queuedBytes_=resultBytes_=0;active=activeStop_;}
    active.request_stop();wake_.notify_all();return result;
}
void ApplicationAnalysisService::submit(std::vector<std::shared_ptr<const Packet>> packets,std::vector<TcpConversation> conversations,std::uint64_t firstRetained) {
    if(packets.empty())return;std::lock_guard lock(mutex_);if(stopped_)return;
    std::size_t bytes=0;for(const auto& p:packets)bytes+=p->raw.bytes.size()+sizeof(Packet);
    if(bytes>applicationBudget/2 || queuedBytes_>applicationBudget/2-bytes) {
        // Budget exhaustion is visible to three-valued filters; packets never look absent.
        auto limited=std::make_shared<ApplicationResult>();limited->status=AnalysisStatus::Limited;
        ApplicationUpdate update;update.generation=generation_;update.result=limited;
        for(const auto& p:packets)update.facts[p->id].status=AnalysisStatus::Limited;
        if(completed_.size()<2048)completed_.push_back(std::move(update));
        return;
    }
    queuedBytes_+=bytes;pending_.push_back({generation_,std::move(packets),std::move(conversations),firstRetained});wake_.notify_one();
}
void ApplicationAnalysisService::setKeyLog(const QString& path){{std::lock_guard lock(mutex_);keyPath_=path;++keyCommand_;}wake_.notify_all();}
void ApplicationAnalysisService::reloadKeyLog(){{std::lock_guard lock(mutex_);++keyCommand_;}wake_.notify_all();}
std::vector<ApplicationUpdate> ApplicationAnalysisService::takeResults(){std::lock_guard lock(mutex_);auto result=std::move(completed_);completed_.clear();resultBytes_=0;wake_.notify_all();return result;}
void ApplicationAnalysisService::requestStop(){std::stop_source active;{std::lock_guard lock(mutex_);stopped_=true;pending_.clear();active=activeStop_;}active.request_stop();thread_.request_stop();wake_.notify_all();}
void ApplicationAnalysisService::run(std::stop_token stop) {
    struct Connection {TcpConversation info;std::deque<std::shared_ptr<const Packet>> packets;std::size_t bytes{};std::uint64_t revision{};bool partial{};};
    std::map<std::uint64_t,Connection> connections;std::deque<std::uint64_t> order;std::size_t retained=0;std::uint64_t epoch=0,keyCommand=0,keyRevision=0;
    QString path;std::unique_ptr<TlsKeyLog> keys=std::make_unique<TlsKeyLog>();qint64 fileSize=-1,fileTime=-1;auto checked=std::chrono::steady_clock::now();
    while(!stop.stop_requested()) {
        std::optional<Batch> batch;std::stop_token token;std::uint64_t current;QString desiredPath;std::uint64_t command;
        {
            std::unique_lock lock(mutex_);wake_.wait_for(lock,stop,std::chrono::milliseconds(250),[&]{return stopped_ || !pending_.empty() || epoch!=generation_ || keyCommand!=keyCommand_;});
            if(stop.stop_requested() || stopped_)break;current=generation_;command=keyCommand_;desiredPath=keyPath_;
            if(!pending_.empty()){batch=std::move(pending_.front());pending_.pop_front();for(const auto& p:batch->packets)queuedBytes_-=p->raw.bytes.size()+sizeof(Packet);}
            working_=bool(batch);activeStop_=std::stop_source{};token=activeStop_.get_token();
        }
        if(epoch!=current){connections.clear();order.clear();retained=0;epoch=current;}
        std::set<std::uint64_t> dirty;
        if(command!=keyCommand || (!path.isEmpty() && std::chrono::steady_clock::now()-checked>=std::chrono::seconds(1))) {
            checked=std::chrono::steady_clock::now();bool success=true;QString error;
            try {
                const QFileInfo info(desiredPath);const auto size=info.size(),time=info.lastModified().toMSecsSinceEpoch();
                if(command!=keyCommand || size!=fileSize || time!=fileTime) {
                    auto next=std::make_unique<TlsKeyLog>();
                    if(!desiredPath.isEmpty()){QFile file(desiredPath);if(size>8*1024*1024 || !file.open(QIODevice::ReadOnly))throw std::runtime_error("TLS key log cannot be read");auto bytes=file.readAll();const auto newline=bytes.lastIndexOf('\n');if(newline>=0)bytes.truncate(newline+1);else bytes.clear();next->append(std::string_view(bytes.constData(),static_cast<std::size_t>(bytes.size())));}
                    keys=std::move(next);++keyRevision;path=desiredPath;fileSize=size;fileTime=time;for(const auto& [id,c]:connections){(void)c;dirty.insert(id);}
                }
            }catch(const std::exception& e){success=false;error=QString::fromUtf8(e.what());}
            keyCommand=command;emit keyLogChanged(success,error);
        }
        std::vector<ApplicationUpdate> results;
        if(batch && batch->generation==epoch) {
            if(batch->firstRetained)for(auto it=connections.begin();it!=connections.end();) {
                auto& c=it->second;
                while(!c.packets.empty() && c.packets.front()->id<batch->firstRetained){retained-=c.packets.front()->raw.bytes.size();c.bytes-=c.packets.front()->raw.bytes.size();c.packets.pop_front();c.partial=true;}
                if(c.packets.empty()){std::erase(order,it->first);dirty.erase(it->first);it=connections.erase(it);}else ++it;
            }
            for(auto& info:batch->conversations)connections[info.id].info=std::move(info);
            for(const auto& packet:batch->packets) {
                if(packet->tcpConversationId) {
                    auto& c=connections[packet->tcpConversationId];
                    if(c.packets.empty())order.push_back(packet->tcpConversationId);
                    const auto size=packet->raw.bytes.size();
                    while(!c.packets.empty() && (c.packets.size()>=streamPacketLimit || c.bytes+size>streamInputLimit)){c.bytes-=c.packets.front()->raw.bytes.size();retained-=c.packets.front()->raw.bytes.size();c.packets.pop_front();c.partial=true;}
                    if(size<=streamInputLimit){c.packets.push_back(packet);c.bytes+=size;retained+=size;}else c.partial=true;
                    ++c.revision;dirty.insert(packet->tcpConversationId);
                }else if(packet->udp && (packet->udp->sourcePort==53 || packet->udp->destinationPort==53)){
                    auto result=std::make_shared<ApplicationResult>(analyzeDatagram(*packet));ApplicationUpdate update;update.generation=epoch;update.keyRevision=keyRevision;update.result=result;
                    const std::array packets{packet};update.facts=indexApplication(*result,packets);results.push_back(std::move(update));
                }
            }
            while((retained>applicationBudget/2 || connections.size()>TcpConversations::connectionLimit) && !order.empty()) {
                const auto id=order.front();order.pop_front();const auto it=connections.find(id);if(it==connections.end())continue;retained-=it->second.bytes;dirty.erase(id);connections.erase(it);
            }
        }
        for(const auto id:dirty) {
            if(token.stop_requested())break;auto it=connections.find(id);if(it==connections.end() || it->second.packets.empty())continue;auto& c=it->second;
            TcpStreamRequest request;request.conversationId=id;request.generation=epoch;request.key=c.info.key;request.cachePartial=c.partial;request.packets.assign(c.packets.begin(),c.packets.end());
            for(unsigned side=0;side<2;++side){if(c.info.syn[side].seen)request.start[side]=c.info.syn[side].sequence+1;if(c.info.finNext[side])request.end[side]=*c.info.finNext[side]-1;}
            if(c.info.initiator>=0 && c.info.synAck.seen)request.start[1-static_cast<unsigned>(c.info.initiator)]=c.info.synAck.sequence+1;
            std::shared_ptr<ApplicationResult> result;
            try{result=std::make_shared<ApplicationResult>(hooks_.conversation?hooks_.conversation(request,*keys,token):analyzeConversation(request,*keys,token));}
            catch(const std::exception& e){result=std::make_shared<ApplicationResult>();result->status=AnalysisStatus::Incomplete;result->error=e.what();}
            ApplicationUpdate update;update.generation=epoch;update.revision=c.revision;update.keyRevision=keyRevision;update.conversation=id;update.facts=indexApplication(*result,request.packets);update.result=std::move(result);results.push_back(std::move(update));
        }
        {
            std::lock_guard lock(mutex_);working_=false;
            if(epoch==generation_ && !token.stop_requested())for(auto& result:results){
                const auto size=result.result?result.result->estimatedBytes:0;
                if(completed_.size()>=2048 || size>applicationBudget/2 || resultBytes_>applicationBudget/2-size)break;
                resultBytes_+=size;completed_.push_back(std::move(result));
            }
        }
        emit changed();
    }
    {std::lock_guard lock(mutex_);working_=false;}emit changed();
}
}
