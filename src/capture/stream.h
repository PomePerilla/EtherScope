#pragma once
#include "core/tcp_stream.h"
#include <QObject>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace etherscope {
using StreamDecoder=std::function<TcpStreamResult(const TcpStreamRequest&,std::stop_token)>;
class StreamService final:public QObject {
    Q_OBJECT
public:
    struct Result {
        quint64 request{};
        std::shared_ptr<const TcpStreamResult> stream;
        QString error;
    };
    explicit StreamService(QObject* parent=nullptr,StreamDecoder decoder={});
    ~StreamService() override;
    quint64 request(TcpStreamRequest request);
    void cancel();
    void requestStop();
    bool busy() const;
    std::optional<Result> takeResult();
signals:
    void changed();
private:
    struct Job {quint64 id{};TcpStreamRequest request;};
    StreamDecoder decoder_;
    mutable std::mutex mutex_;
    std::condition_variable_any wake_;
    std::optional<Job> pending_;
    std::optional<Result> completed_;
    bool working_{},stopped_{};
    quint64 generation_{};
    std::stop_source activeStop_;
    std::jthread worker_;
};
}
