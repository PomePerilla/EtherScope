#pragma once
#include "core/packet.h"
#include "core/tcp_conversations.h"
#include <deque>
#include <map>
#include <memory>

namespace etherscope {
struct SessionStats {
    std::uint64_t received{}, wireBytes{}, overwritten{}, malformed{};
    std::map<std::string, std::uint64_t> protocols;
};
struct SessionDelta {
    std::uint64_t first{}, last{}, through{};
    std::vector<std::shared_ptr<const Packet>> added;
};
class SessionStore {
  public:
    explicit SessionStore(std::size_t maxPackets = 10000, std::size_t maxBytes = 64 * 1024 * 1024,
                          std::size_t maxEstimatedBytes = 64 * 1024 * 1024);
    void append(Packet packet);
    void clear();
    SessionDelta deltaAfter(std::uint64_t id) const;
    std::shared_ptr<const Packet> find(std::uint64_t id) const;
    const std::deque<std::shared_ptr<const Packet>> &packets() const {
        return packets_;
    }
    const SessionStats &stats() const {
        return stats_;
    }
    std::size_t rawBytes() const {
        return rawBytes_;
    }
    std::size_t estimatedBytes() const {
        return estimatedBytes_;
    }
    const TcpConversations &tcp() const {
        return tcp_;
    }

  private:
    std::size_t maxPackets_, maxBytes_, rawBytes_{};
    std::size_t maxEstimatedBytes_, estimatedBytes_{};
    std::uint64_t nextId_{1};
    SessionStats stats_;
    TcpConversations tcp_;
    std::deque<std::shared_ptr<const Packet>> packets_;
};
} // namespace etherscope
