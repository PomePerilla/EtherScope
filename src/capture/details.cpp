#include "capture/details.h"

namespace etherscope {
DetailService::DetailService(QObject* parent,DetailDecoder decoder):QObject(parent),decoder_(std::move(decoder)),
    worker_([this](std::stop_token stop){
        for(;;) {
            Result job;std::stop_token jobStop;
            {
                std::unique_lock lock(mutex_);
                if(!wake_.wait(lock,stop,[this]{return pending_.has_value();}))break;
                job=std::move(*pending_);pending_.reset();working_=true;activeStop_=std::stop_source{};jobStop=activeStop_.get_token();
            }
            try {
                if(decoder_)job.details=std::make_shared<PacketDetails>(decoder_(job.packet->raw,jobStop));
                else if(job.packet->fields.empty())job.details=std::make_shared<PacketDetails>(decodeDetails(job.packet->raw));
                else job.details=std::make_shared<PacketDetails>(PacketDetails{job.packet->fields,job.packet->estimatedBytes-job.packet->raw.bytes.capacity()});
            }
            catch(const std::exception& error){job.error=QString::fromUtf8(error.what());}
            {
                std::lock_guard lock(mutex_);working_=false;
                if(!stop.stop_requested() && job.request==generation_)completed_=std::move(job);
            }
            emit changed();
        }
        emit changed();
    }) {}
DetailService::~DetailService() {requestStop();if(worker_.joinable())worker_.join();}
quint64 DetailService::request(std::shared_ptr<const Packet> packet) {
    std::stop_source previous;quint64 request;
    {std::lock_guard lock(mutex_);request=++generation_;previous=activeStop_;completed_.reset();pending_=Result{request,std::move(packet),{}, {}};}
    previous.request_stop();wake_.notify_one();return request;
}
void DetailService::cancel() {
    std::stop_source previous;
    {std::lock_guard lock(mutex_);++generation_;previous=activeStop_;pending_.reset();completed_.reset();}
    previous.request_stop();
}
void DetailService::requestStop() {cancel();worker_.request_stop();wake_.notify_all();}
bool DetailService::busy() const {std::lock_guard lock(mutex_);return working_ || pending_.has_value();}
std::optional<DetailService::Result> DetailService::takeResult() {std::lock_guard lock(mutex_);auto value=std::move(completed_);completed_.reset();return value;}
}
