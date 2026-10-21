#pragma once
#include "core/application_analyzer.h"
#include <QObject>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace etherscope {
struct ApplicationUpdate {
    std::uint64_t generation{}, revision{}, keyRevision{}, conversation{}, keyCommand{};
    bool keySensitive{};
    std::shared_ptr<const ApplicationResult> result;
    std::map<std::uint64_t, ApplicationFacts> facts;
    std::vector<std::uint64_t> limitedPackets;
};
struct ApplicationHooks {
    std::function<ApplicationResult(const TcpStreamRequest &, const TlsKeyLog &, std::stop_token)>
        conversation;
};
struct ApplicationServiceStats {
    std::uint64_t submittedPackets{}, rejectedPackets{}, completedUpdates{}, deliveredBytes{},
        keyReplays{}, stateEvictions{};
    std::size_t stateBytes{}, retainedBytes{}, queuedBytes{}, pendingUpdates{};
};
class ApplicationAnalysisService final : public QObject {
    Q_OBJECT
  public:
    explicit ApplicationAnalysisService(QObject *parent = nullptr, ApplicationHooks hooks = {});
    ~ApplicationAnalysisService() override;
    std::uint64_t reset();
    void submit(std::vector<std::shared_ptr<const Packet>> packets,
                std::vector<TcpConversation> conversations, std::uint64_t firstRetained = 0);
    void setKeyLog(const QString &path);
    void reloadKeyLog();
    std::vector<ApplicationUpdate> takeResults();
    std::uint64_t generation() const;
    bool accepts(const ApplicationUpdate &update) const;
    bool busy() const;
    ApplicationServiceStats stats() const;
    void requestStop();
  signals:
    void changed();
    void keyLogChanged(bool success, const QString &error);

  private:
    struct Batch {
        std::uint64_t generation;
        std::vector<std::shared_ptr<const Packet>> packets;
        std::vector<TcpConversation> conversations;
        std::uint64_t firstRetained{};
    };
    ApplicationHooks hooks_;
    mutable std::mutex mutex_;
    std::condition_variable_any wake_;
    std::deque<Batch> pending_;
    std::vector<ApplicationUpdate> completed_;
    std::map<std::uint64_t, ApplicationFacts> limited_;
    std::uint64_t generation_{1}, keyCommand_{}, retentionFloor_{};
    std::size_t queuedBytes_{}, resultBytes_{};
    ApplicationServiceStats stats_;
    QString keyPath_;
    bool working_{}, stopped_{};
    std::stop_source activeStop_;
    std::jthread thread_;
    void run(std::stop_token stop);
};
} // namespace etherscope
