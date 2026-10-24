#pragma once
#include "core/packet.h"
#include "core/capture_file.h"
#include <QObject>
#include <QString>
#include <atomic>
#include <functional>
#include <memory>
#include <thread>

class QIODevice;
namespace etherscope {
using PacketSnapshot = std::vector<std::shared_ptr<const Packet>>;
// Optional I/O injection for deterministic slow-write and failure tests.
using ExportWriter = std::function<qint64(QIODevice &, const char *, qint64)>;
class ExportEngine final : public QObject {
    Q_OBJECT
  public:
    explicit ExportEngine(QObject *parent = nullptr, ExportWriter writer = {});
    ~ExportEngine() override;
    bool start(const QString &path, PacketSnapshot snapshot,
               CaptureFormat format = CaptureFormat::Pcap);
    bool running() const {
        return running_.load();
    }
    quint64 generation() const {
        return generation_;
    }
    std::size_t referencedBytes() const {
        return referencedBytes_;
    }
  signals:
    // Completed packet count; the final progress event follows a successful atomic commit.
    void progress(quint64 job, quint64 completed, quint64 total);
    void finished(quint64 job, bool success, const QString &path, quint64 count,
                  const QString &error);

  private:
    ExportWriter writer_;
    std::jthread worker_;
    std::atomic<bool> running_{};
    std::atomic<std::size_t> referencedBytes_{};
    quint64 generation_{};
};
} // namespace etherscope
