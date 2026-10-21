#include "capture/stream.h"
namespace etherscope {
StreamService::StreamService(QObject *parent, StreamDecoder decoder) : QObject(parent) {
    task_ = std::make_unique<LatestTask<TcpStreamRequest, Result>>(
        [decoder = std::move(decoder)](TcpStreamRequest request, std::stop_token stop) {
            Result result;
            result.stream = std::make_shared<TcpStreamResult>(
                decoder ? decoder(request, stop) : reassembleTcp(request, stop));
            return result;
        },
        [this] { emit changed(); });
}
StreamService::~StreamService() = default;
quint64 StreamService::request(TcpStreamRequest request) {
    return task_->request(std::move(request));
}
void StreamService::cancel() {
    task_->cancel();
}
void StreamService::requestStop() {
    task_->stop();
}
bool StreamService::busy() const {
    return task_->busy();
}
std::optional<StreamService::Result> StreamService::takeResult() {
    return task_->take();
}
} // namespace etherscope
