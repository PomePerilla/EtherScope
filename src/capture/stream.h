#pragma once
#include "core/tcp_stream.h"
#include "capture/latest_task.h"
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
    std::unique_ptr<LatestTask<TcpStreamRequest,Result>> task_;
};
}
