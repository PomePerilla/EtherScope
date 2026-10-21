#pragma once
#include "core/packet.h"
#include <QObject>
#include <QString>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace etherscope {
class PcapReader;
using PreparedFile=std::shared_ptr<PcapReader>;
struct CaptureInterface { QString name, description, addresses; };
struct LiveCaptureOptions { QString bpf; };
struct CaptureCounters {
    std::uint64_t received{},bytes{},queueDropped{};
    std::uint64_t untimedPackets{},untimedBytes{};
    std::optional<std::uint64_t> driverDropped;
    std::uint64_t enqueued{},queuedPackets{},queuedBytes{},peakQueuedPackets{},peakQueuedBytes{};
    std::uint64_t queuedEstimatedBytes{},peakQueuedEstimatedBytes{},waitWakeups{};
    QString waitStrategy;
};
struct CaptureHooks {
    using Sink=std::function<void(RawPacket)>;
    using Opened=std::function<void(const QString&)>;
    std::function<std::vector<CaptureInterface>(QString&)> interfaces;
    std::function<void(const QString&,bool,std::stop_token,const Sink&,const Opened&,const LiveCaptureOptions&)> run;
    bool disableDataEvent{};
    std::function<void(const RawPacket&)> rawObserver;
};
class CaptureEngine final:public QObject {
    Q_OBJECT
public:
    explicit CaptureEngine(QObject* parent=nullptr,CaptureHooks hooks={});
    ~CaptureEngine() override;
    std::vector<CaptureInterface> interfaces(QString& error);
    void startLive(const QString& device,LiveCaptureOptions options={});
    void startFile(const QString& path,PreparedFile reader={});
    void stop();
    void requestStop();
    bool running() const { return running_.load(); }
    quint64 generation() const { return generation_; }
    std::vector<Packet> takeBatch(std::size_t maxPackets=8192);
    CaptureCounters counters() const;
signals:
    void failed(quint64 generation,const QString& message);
    void opened(quint64 generation,const QString& message);
    void finished(quint64 generation);
private:
    struct Api;
    std::unique_ptr<Api> api_;
    CaptureHooks hooks_;
    std::jthread worker_;
    mutable std::mutex mutex_;
    std::condition_variable_any queueSpace_;
    std::deque<Packet> queue_;
    std::size_t queuedBytes_{};
    std::size_t queuedEstimatedBytes_{};
    std::uint64_t peakQueuedEstimatedBytes_{};
    std::atomic<std::uint64_t> waitWakeups_{};
    std::atomic<int> waitStrategy_{};
    std::uint64_t enqueued_{},peakQueuedPackets_{},peakQueuedBytes_{};
    std::atomic<bool> running_{};
    std::atomic<std::uint64_t> received_{},bytes_{},queueDropped_{};
    std::atomic<std::uint64_t> untimedPackets_{},untimedBytes_{};
    std::atomic<std::int64_t> driverDropped_{-1};
    quint64 generation_{};
    void reset();
    void enqueue(RawPacket raw,bool file,std::stop_token stop);
    void start(const QString& target,bool file,PreparedFile reader={},LiveCaptureOptions options={});
    void runLive(const QString& device,quint64 epoch,std::stop_token stop,const LiveCaptureOptions& options);
    void runFile(const QString& path,quint64 epoch,std::stop_token stop,PreparedFile reader);
};
}
