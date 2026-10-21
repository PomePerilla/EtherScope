#include "capture/application_service.h"
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <algorithm>
#include <set>
#include <utility>

namespace etherscope {
ApplicationAnalysisService::ApplicationAnalysisService(QObject *parent, ApplicationHooks hooks)
    : QObject(parent), hooks_(std::move(hooks)),
      thread_([this](std::stop_token stop) { run(stop); }) {}
ApplicationAnalysisService::~ApplicationAnalysisService() {
    requestStop();
    if (thread_.joinable())
        thread_.join();
}
std::uint64_t ApplicationAnalysisService::generation() const {
    std::lock_guard lock(mutex_);
    return generation_;
}
bool ApplicationAnalysisService::busy() const {
    std::lock_guard lock(mutex_);
    return working_ || !pending_.empty();
}
bool ApplicationAnalysisService::accepts(const ApplicationUpdate &update) const {
    std::lock_guard lock(mutex_);
    return update.generation == generation_ &&
           (!update.keySensitive || update.keyCommand == keyCommand_);
}
ApplicationServiceStats ApplicationAnalysisService::stats() const {
    std::lock_guard lock(mutex_);
    auto result = stats_;
    result.queuedBytes = queuedBytes_;
    result.pendingUpdates = completed_.size() + (limited_.empty() ? 0 : 1);
    return result;
}
std::uint64_t ApplicationAnalysisService::reset() {
    std::stop_source active;
    std::uint64_t result;
    {
        std::lock_guard lock(mutex_);
        result = ++generation_;
        pending_.clear();
        completed_.clear();
        limited_.clear();
        queuedBytes_ = resultBytes_ = 0;
        stats_ = {};
        retentionFloor_ = 0;
        active = activeStop_;
    }
    active.request_stop();
    wake_.notify_all();
    return result;
}
void ApplicationAnalysisService::submit(std::vector<std::shared_ptr<const Packet>> packets,
                                        std::vector<TcpConversation> conversations,
                                        std::uint64_t firstRetained) {
    if (packets.empty())
        return;
    std::unique_lock lock(mutex_);
    if (stopped_)
        return;
    retentionFloor_ = std::max(retentionFloor_, firstRetained);
    stats_.submittedPackets += packets.size();
    std::size_t bytes = conversations.capacity() * sizeof(TcpConversation);
    for (const auto &p : packets)
        bytes += p->estimatedBytes + sizeof(std::shared_ptr<const Packet>);
    if (bytes > applicationQueueBudget || queuedBytes_ > applicationQueueBudget - bytes) {
        stats_.rejectedPackets += packets.size();
        // Budget exhaustion is visible to three-valued filters; packets never look absent.
        for (const auto &p : packets)
            limited_[p->id].status = AnalysisStatus::Limited;
        while (limited_.size() > 10000)
            limited_.erase(limited_.begin());
        lock.unlock();
        wake_.notify_one();
        emit changed();
        return;
    }
    queuedBytes_ += bytes;
    pending_.push_back({generation_, std::move(packets), std::move(conversations), firstRetained});
    wake_.notify_one();
}
void ApplicationAnalysisService::setKeyLog(const QString &path) {
    {
        std::lock_guard lock(mutex_);
        keyPath_ = path;
        ++keyCommand_;
    }
    wake_.notify_all();
}
void ApplicationAnalysisService::reloadKeyLog() {
    {
        std::lock_guard lock(mutex_);
        ++keyCommand_;
    }
    wake_.notify_all();
}
std::vector<ApplicationUpdate> ApplicationAnalysisService::takeResults() {
    std::lock_guard lock(mutex_);
    auto result = std::move(completed_);
    completed_.clear();
    resultBytes_ = 0;
    if (!limited_.empty()) {
        auto limited = std::make_shared<ApplicationResult>();
        limited->status = AnalysisStatus::Limited;
        ApplicationUpdate update;
        update.generation = generation_;
        update.keyCommand = keyCommand_;
        update.result = std::move(limited);
        update.facts = std::move(limited_);
        result.push_back(std::move(update));
        limited_.clear();
    }
    wake_.notify_all();
    return result;
}
void ApplicationAnalysisService::requestStop() {
    std::stop_source active;
    {
        std::lock_guard lock(mutex_);
        stopped_ = true;
        pending_.clear();
        active = activeStop_;
    }
    active.request_stop();
    thread_.request_stop();
    wake_.notify_all();
}
void ApplicationAnalysisService::run(std::stop_token stop) {
    struct Connection {
        TcpConversation info;
        std::deque<std::shared_ptr<const Packet>> packets;
        std::size_t bytes{};
        std::uint64_t revision{};
        bool partial{}, ordered{};
        std::vector<std::shared_ptr<const Packet>> incoming;
        std::unique_ptr<ConversationAnalysis> analysis;
        std::size_t analysisBytes{};
    };
    std::map<std::uint64_t, Connection> connections;
    std::deque<std::uint64_t> order;
    std::size_t retained = 0;
    std::size_t analysisBytes = 0;
    std::uint64_t epoch = 0, keyCommand = 0, keyRevision = 0, appliedFloor = 0;
    QString path;
    std::unique_ptr<TlsKeyLog> keys = std::make_unique<TlsKeyLog>();
    qint64 fileSize = -1, fileTime = -1;
    auto checked = std::chrono::steady_clock::now();
    while (!stop.stop_requested()) {
        std::optional<Batch> batch;
        std::stop_token token;
        std::uint64_t current;
        QString desiredPath;
        std::uint64_t command, floor;
        {
            std::unique_lock lock(mutex_);
            wake_.wait_for(lock, stop, std::chrono::milliseconds(250), [&] {
                return stopped_ || !pending_.empty() || epoch != generation_ ||
                       keyCommand != keyCommand_ || appliedFloor != retentionFloor_;
            });
            if (stop.stop_requested() || stopped_)
                break;
            current = generation_;
            command = keyCommand_;
            floor = retentionFloor_;
            desiredPath = keyPath_;
            if (!pending_.empty()) {
                batch = std::move(pending_.front());
                pending_.pop_front();
                queuedBytes_ -= batch->conversations.capacity() * sizeof(TcpConversation);
                for (const auto &p : batch->packets)
                    queuedBytes_ -= p->estimatedBytes + sizeof(std::shared_ptr<const Packet>);
            }
            working_ = true;
            activeStop_ = std::stop_source{};
            token = activeStop_.get_token();
        }
        if (epoch != current) {
            connections.clear();
            order.clear();
            retained = 0;
            analysisBytes = 0;
            epoch = current;
        }
        std::set<std::uint64_t> dirty;
        if (command != keyCommand ||
            (!path.isEmpty() &&
             std::chrono::steady_clock::now() - checked >= std::chrono::seconds(1))) {
            checked = std::chrono::steady_clock::now();
            bool success = true;
            QString error;
            try {
                const QFileInfo info(desiredPath);
                const auto size = info.size(), time = info.lastModified().toMSecsSinceEpoch();
                if (command != keyCommand || size != fileSize || time != fileTime) {
                    auto next = std::make_unique<TlsKeyLog>();
                    if (!desiredPath.isEmpty()) {
                        QFile file(desiredPath);
                        if (size > qint64(applicationKeyLogLimit) ||
                            !file.open(QIODevice::ReadOnly))
                            throw std::runtime_error("TLS key log cannot be read");
                        auto bytes = file.read(applicationKeyLogLimit + 1);
                        if (bytes.size() > qint64(applicationKeyLogLimit))
                            throw std::length_error("TLS key log exceeds limit");
                        if (command == keyCommand) {
                            const auto newline = bytes.lastIndexOf('\n');
                            if (newline >= 0)
                                bytes.truncate(newline + 1);
                            else
                                bytes.clear();
                        }
                        next->append(std::string_view(bytes.constData(),
                                                      static_cast<std::size_t>(bytes.size())));
                    }
                    for (auto &[id, connection] : connections)
                        if (hooks_.conversation ||
                            (connection.analysis &&
                             connection.analysis->keysChanged(*keys, *next))) {
                            analysisBytes -= connection.analysisBytes;
                            connection.analysisBytes = 0;
                            connection.analysis.reset();
                            connection.incoming.assign(connection.packets.begin(),
                                                       connection.packets.end());
                            dirty.insert(id);
                            std::lock_guard lock(mutex_);
                            ++stats_.keyReplays;
                        }
                    keys = std::move(next);
                    ++keyRevision;
                    path = desiredPath;
                    fileSize = size;
                    fileTime = time;
                }
            } catch (const std::exception &e) {
                success = false;
                error = QString::fromUtf8(e.what());
            }
            keyCommand = command;
            emit keyLogChanged(success, error);
        }
        std::vector<ApplicationUpdate> results;
        // Cache eviction must release references even when a new batch is rejected.
        if (floor != appliedFloor) {
            appliedFloor = floor;
            if (floor)
                for (auto it = connections.begin(); it != connections.end();) {
                    auto &c = it->second;
                    while (!c.packets.empty() && c.packets.front()->id < floor) {
                        retained -= c.packets.front()->estimatedBytes;
                        c.bytes -= c.packets.front()->estimatedBytes;
                        c.packets.pop_front();
                        c.partial = true;
                    }
                    std::erase_if(c.incoming,
                                  [floor](const auto &packet) { return packet->id < floor; });
                    if (c.analysis) {
                        analysisBytes -= c.analysisBytes;
                        c.analysis->prune(floor);
                        c.analysisBytes = c.analysis->estimatedBytes();
                        analysisBytes += c.analysisBytes;
                    }
                    if (c.packets.empty() && !c.analysis) {
                        std::erase(order, it->first);
                        dirty.erase(it->first);
                        it = connections.erase(it);
                    } else
                        ++it;
                }
        }
        if (batch && batch->generation == epoch) {
            std::set<std::uint64_t> activeIds;
            for (const auto &packet : batch->packets)
                if (packet->id >= floor && packet->tcpConversationId)
                    activeIds.insert(packet->tcpConversationId);
            for (auto &info : batch->conversations)
                if (activeIds.contains(info.id))
                    connections[info.id].info = std::move(info);
            for (const auto &packet : batch->packets) {
                if (packet->id < floor)
                    continue;
                if (packet->tcpConversationId) {
                    auto &c = connections[packet->tcpConversationId];
                    if (!c.ordered) {
                        order.push_back(packet->tcpConversationId);
                        c.ordered = true;
                    }
                    const auto size = packet->estimatedBytes;
                    while (!c.packets.empty() &&
                           (c.packets.size() >= 10000 || c.bytes + size > applicationInputBudget)) {
                        c.bytes -= c.packets.front()->estimatedBytes;
                        retained -= c.packets.front()->estimatedBytes;
                        const auto removed = c.packets.front()->id;
                        c.packets.pop_front();
                        std::erase_if(c.incoming, [removed](const auto &value) {
                            return value->id <= removed;
                        });
                        c.partial = true;
                    }
                    if (size <= applicationInputBudget) {
                        c.packets.push_back(packet);
                        c.incoming.push_back(packet);
                        c.bytes += size;
                        retained += size;
                    } else
                        c.partial = true;
                    ++c.revision;
                    dirty.insert(packet->tcpConversationId);
                } else if (packet->udp &&
                           (packet->udp->sourcePort == 53 || packet->udp->destinationPort == 53)) {
                    auto result = std::make_shared<ApplicationResult>(analyzeDatagram(*packet));
                    ApplicationUpdate update;
                    update.generation = epoch;
                    update.keyRevision = keyRevision;
                    update.result = result;
                    const std::array packets{packet};
                    update.facts = indexApplication(*result, packets);
                    results.push_back(std::move(update));
                }
            }
            while (((retained > applicationInputBudget || analysisBytes > applicationStateBudget) ||
                    connections.size() > TcpConversations::connectionLimit) &&
                   !order.empty()) {
                const auto id = order.front();
                order.pop_front();
                const auto it = connections.find(id);
                if (it == connections.end())
                    continue;
                ApplicationUpdate update;
                update.generation = epoch;
                auto result = std::make_shared<ApplicationResult>();
                result->status = AnalysisStatus::Limited;
                update.result = std::move(result);
                // Releasing computation state does not invalidate already published facts.
                for (const auto &packet : it->second.incoming)
                    update.facts[packet->id].status = AnalysisStatus::Limited;
                if (!update.facts.empty())
                    results.push_back(std::move(update));
                retained -= it->second.bytes;
                analysisBytes -= it->second.analysisBytes;
                {
                    std::lock_guard lock(mutex_);
                    ++stats_.stateEvictions;
                }
                dirty.erase(id);
                connections.erase(it);
            }
        }
        for (const auto id : dirty) {
            if (token.stop_requested())
                break;
            auto it = connections.find(id);
            if (it == connections.end() || it->second.packets.empty())
                continue;
            auto &c = it->second;
            TcpStreamRequest request;
            request.conversationId = id;
            request.generation = epoch;
            request.key = c.info.key;
            request.cachePartial = c.partial;
            if (hooks_.conversation) {
                request.packets.assign(c.packets.begin(), c.packets.end());
                c.incoming.clear();
            } else
                request.packets = std::exchange(c.incoming, {});
            for (unsigned side = 0; side < 2; ++side) {
                if (c.info.syn[side].seen)
                    request.start[side] = c.info.syn[side].sequence + 1;
                if (c.info.finNext[side])
                    request.end[side] = *c.info.finNext[side] - 1;
            }
            if (c.info.initiator >= 0 && c.info.synAck.seen)
                request.start[1 - static_cast<unsigned>(c.info.initiator)] =
                    c.info.synAck.sequence + 1;
            std::shared_ptr<ApplicationResult> result;
            try {
                if (c.info.id != id) {
                    result = std::make_shared<ApplicationResult>();
                    result->status = AnalysisStatus::Limited;
                } else {
                    if (hooks_.conversation)
                        result = std::make_shared<ApplicationResult>(
                            hooks_.conversation(request, *keys, token));
                    else {
                        if (!c.analysis)
                            c.analysis = std::make_unique<ConversationAnalysis>();
                        const auto before = c.analysis->deliveredBytes();
                        c.analysis->prune(floor);
                        result = std::make_shared<ApplicationResult>(
                            c.analysis->append(request, *keys, token));
                        analysisBytes -= c.analysisBytes;
                        c.analysisBytes = c.analysis->estimatedBytes();
                        analysisBytes += c.analysisBytes;
                        std::lock_guard lock(mutex_);
                        if (epoch == generation_)
                            stats_.deliveredBytes += c.analysis->deliveredBytes() - before;
                    }
                }
            } catch (const std::exception &e) {
                result = std::make_shared<ApplicationResult>();
                result->status = AnalysisStatus::Incomplete;
                result->error = e.what();
            }
            ApplicationUpdate update;
            update.generation = epoch;
            update.revision = c.revision;
            update.keyRevision = keyRevision;
            update.conversation = id;
            const std::vector<std::shared_ptr<const Packet>> retainedPackets(c.packets.begin(),
                                                                             c.packets.end());
            update.facts = indexApplication(*result, retainedPackets);
            update.result = std::move(result);
            results.push_back(std::move(update));
        }
        while ((retained > applicationInputBudget || analysisBytes > applicationStateBudget) &&
               !order.empty()) {
            const auto id = order.front();
            order.pop_front();
            const auto found = connections.find(id);
            if (found == connections.end())
                continue;
            retained -= found->second.bytes;
            analysisBytes -= found->second.analysisBytes;
            connections.erase(found);
            std::lock_guard lock(mutex_);
            ++stats_.stateEvictions;
        }
        {
            std::lock_guard lock(mutex_);
            working_ = false;
            if (epoch == generation_) {
                stats_.stateBytes = analysisBytes;
                stats_.retainedBytes = retained;
            }
            if (epoch == generation_ && !token.stop_requested())
                for (auto &result : results) {
                    result.keyCommand = command;
                    result.keySensitive =
                        result.result &&
                        (result.result->status == AnalysisStatus::MissingKeys ||
                         result.result->status == AnalysisStatus::AuthenticationFailed ||
                         std::any_of(
                             result.result->messages.begin(), result.result->messages.end(),
                             [](const auto &message) { return message.protocol == "TLS"; }));
                    const auto size = sizeof(ApplicationUpdate) +
                                      estimateApplicationFacts(result.facts) +
                                      (result.result ? result.result->estimatedBytes : 0);
                    if (completed_.size() >= 2048 ||
                        size > applicationStagingBudget - 1024 * 1024 ||
                        resultBytes_ > applicationStagingBudget - 1024 * 1024 - size) {
                        for (const auto &[id, fact] : result.facts) {
                            (void)fact;
                            limited_[id].status = AnalysisStatus::Limited;
                        }
                        while (limited_.size() > 10000)
                            limited_.erase(limited_.begin());
                        continue;
                    }
                    // A completed replay supersedes earlier queue or staging limit markers.
                    for (const auto &[id, fact] : result.facts) {
                        (void)fact;
                        limited_.erase(id);
                    }
                    resultBytes_ += size;
                    ++stats_.completedUpdates;
                    completed_.push_back(std::move(result));
                }
        }
        emit changed();
    }
    {
        std::lock_guard lock(mutex_);
        working_ = false;
    }
    emit changed();
}
} // namespace etherscope
