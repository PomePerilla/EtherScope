#pragma once
#include "core/packet.h"
#include <QObject>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace etherscope {
using DetailDecoder=std::function<PacketDetails(const RawPacket&,std::stop_token)>;
class DetailService final:public QObject {
    Q_OBJECT
public:
    struct Result {
        quint64 request{};
        std::shared_ptr<const Packet> packet;
        std::shared_ptr<const PacketDetails> details;
        QString error;
    };
    explicit DetailService(QObject* parent=nullptr,DetailDecoder decoder={});
    ~DetailService() override;
    quint64 request(std::shared_ptr<const Packet> packet);
    void cancel();
    void requestStop();
    bool busy() const;
    std::optional<Result> takeResult();
signals:
    void changed();
private:
    DetailDecoder decoder_;
    mutable std::mutex mutex_;
    std::condition_variable_any wake_;
    std::optional<Result> pending_,completed_;
    bool working_{};
    quint64 generation_{};
    std::stop_source activeStop_;
    std::jthread worker_;
};
}
