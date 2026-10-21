#pragma once
#include "capture/export.h"
#include <QObject>
#include <condition_variable>
#include <deque>
#include <mutex>

namespace etherscope {
struct RecordingOptions {
    bool enabled{};
    QString directory;
    std::uint64_t fileBytes{128*1024*1024},durationMs{300000},diskBytes{1024*1024*1024};
};
struct RecordingStats {
    std::uint64_t written{},queued{},unwritten{},bytesWritten{},diskBytes{};
    bool failed{};
    QString directory,error;
};
struct RecordingHooks {
    ExportWriter write;
    std::function<bool(const QString&)> remove;
    std::function<std::chrono::steady_clock::time_point()> now;
};
class RecordingService final:public QObject {
    Q_OBJECT
public:
    explicit RecordingService(QObject* parent=nullptr,RecordingHooks hooks={});
    ~RecordingService() override;
    bool start(RecordingOptions options);
    void submit(const RawPacket& raw);
    void finish();
    bool running() const {return running_;}
    quint64 generation() const {return generation_;}
    RecordingStats stats() const;
signals:
    void finished(quint64 request,bool success,const QString& error);
private:
    RecordingHooks hooks_;
    std::jthread thread_;
    mutable std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<RawPacket> queue_;
    std::size_t queueBytes_{};
    bool accepting_{},finishing_{};
    std::atomic<bool> running_{};
    RecordingStats stats_;
    quint64 generation_{};
    void run(RecordingOptions options,quint64 request);
};
}
