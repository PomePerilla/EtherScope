#include "capture/details.h"
namespace etherscope {
DetailService::DetailService(QObject* parent,DetailDecoder decoder):QObject(parent) {
    task_=std::make_unique<LatestTask<std::shared_ptr<const Packet>,Result>>(
        [decoder=std::move(decoder)](std::shared_ptr<const Packet> packet,std::stop_token stop){
            Result result;result.packet=std::move(packet);
            if(decoder)result.details=std::make_shared<PacketDetails>(decoder(result.packet->raw,stop));
            else if(result.packet->fields.empty())result.details=std::make_shared<PacketDetails>(decodeDetails(result.packet->raw));
            else result.details=std::make_shared<PacketDetails>(PacketDetails{result.packet->fields,result.packet->estimatedBytes-result.packet->raw.bytes.capacity()});
            return result;
        },[this]{emit changed();});
}
DetailService::~DetailService()=default;
quint64 DetailService::request(std::shared_ptr<const Packet> packet){return task_->request(std::move(packet));}
void DetailService::cancel(){task_->cancel();}
void DetailService::requestStop(){task_->stop();}
bool DetailService::busy() const{return task_->busy();}
std::optional<DetailService::Result> DetailService::takeResult(){return task_->take();}
}
