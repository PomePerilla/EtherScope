#include "capture/stream.h"

namespace etherscope {
StreamService::StreamService(QObject* parent,StreamDecoder decoder):QObject(parent),decoder_(std::move(decoder)),worker_([this](std::stop_token stop){
    for(;;) {
        Job job;std::stop_token jobStop;
        {
            std::unique_lock lock(mutex_);
            if(!wake_.wait(lock,stop,[this]{return pending_.has_value();}))break;
            job=std::move(*pending_);pending_.reset();working_=true;activeStop_=std::stop_source{};jobStop=activeStop_.get_token();
        }
        Result result;result.request=job.id;
        try {result.stream=std::make_shared<TcpStreamResult>(decoder_?decoder_(job.request,jobStop):reassembleTcp(job.request,jobStop));}
        catch(const std::exception& error){result.error=QString::fromUtf8(error.what());}
        job.request.packets.clear();
        {
            std::lock_guard lock(mutex_);working_=false;
            if(!stop.stop_requested() && job.id==generation_)completed_=std::move(result);
        }
        emit changed();
    }
    emit changed();
}) {}
StreamService::~StreamService(){requestStop();if(worker_.joinable())worker_.join();}
quint64 StreamService::request(TcpStreamRequest request) {
    std::stop_source previous;quint64 id;
    {std::lock_guard lock(mutex_);if(stopped_)return 0;id=++generation_;previous=activeStop_;completed_.reset();pending_=Job{id,std::move(request)};}
    previous.request_stop();wake_.notify_one();return id;
}
void StreamService::cancel() {
    std::stop_source previous;
    {std::lock_guard lock(mutex_);++generation_;previous=activeStop_;pending_.reset();completed_.reset();}
    previous.request_stop();
}
void StreamService::requestStop() {
    {std::lock_guard lock(mutex_);stopped_=true;}
    cancel();worker_.request_stop();wake_.notify_all();
}
bool StreamService::busy() const {std::lock_guard lock(mutex_);return working_ || pending_.has_value();}
std::optional<StreamService::Result> StreamService::takeResult() {std::lock_guard lock(mutex_);auto result=std::move(completed_);completed_.reset();return result;}
}
