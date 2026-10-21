#pragma once
#include "core/packet.h"
#include <compare>
#include <list>
#include <map>

namespace etherscope {
struct TcpEndpoint {
    auto operator<=>(const TcpEndpoint &) const = default;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port{};
    bool ipv6{};
};
struct TcpKey {
    auto operator<=>(const TcpKey &) const = default;
    TcpEndpoint a, b;
    std::optional<std::uint16_t> vlan;
    std::uint32_t interfaceId{};
};
std::string formatEndpointAddress(const TcpEndpoint &endpoint);
enum class TcpState { Midstream, Handshake, Established, Closing, Closed, Reset };
enum class TcpEventKind { Syn, SynAck, Handshake, Fin, Reset, FinAcknowledged };
struct TcpEvent {
    std::uint64_t packetId{};
    std::int64_t timestampNs{};
    std::uint32_t sequence{}, acknowledgment{};
    TcpEventKind kind{};
    unsigned direction{};
    bool timestampValid{true};
};
struct TcpConversation {
    std::uint64_t id{};
    TcpKey key;
    std::array<std::uint64_t, 2> packets{}, wireBytes{}, payloadBytes{};
    std::int64_t firstNs{}, lastNs{};
    bool hasTimestamps{};
    TcpState state{TcpState::Midstream};
    std::optional<std::uint64_t> synAckNs, handshakeNs;
    std::uint64_t synRepeats{}, resets{}, eventsOverwritten{};
    static constexpr std::size_t eventLimit = 16;
    std::array<TcpEvent, eventLimit> events{};
    std::size_t eventStart{}, eventCount{};
    // Capture observations, not endpoint socket state.
    struct Syn {
        std::uint32_t sequence{}, next{};
        std::int64_t timestampNs{};
        bool seen{};
        bool timestampValid{true};
    };
    std::array<Syn, 2> syn{};
    Syn synAck;
    int initiator{-1};
    bool simultaneousOpen{}, handshakeSeen{};
    std::array<std::optional<std::uint32_t>, 2> finNext;
    std::array<bool, 2> finAcked{};
};
class TcpConversations {
  public:
    static constexpr std::size_t connectionLimit = 1024;
    explicit TcpConversations(std::size_t maximum = connectionLimit);
    TcpConversations(const TcpConversations &) = delete;
    TcpConversations &operator=(const TcpConversations &) = delete;
    void observe(Packet &packet);
    void clear();
    const std::list<TcpConversation> &items() const {
        return items_;
    }
    const TcpConversation *find(std::uint64_t id) const;
    std::size_t estimatedBytes() const;
    std::uint64_t overwritten() const {
        return overwritten_;
    }
    std::uint64_t skipped() const {
        return skipped_;
    }
    std::uint64_t revision() const {
        return revision_;
    }
    std::uint64_t generation() const {
        return generation_;
    }

  private:
    std::size_t maximum_;
    std::uint64_t nextId_{1}, overwritten_{}, skipped_{}, revision_{}, generation_{1};
    std::list<TcpConversation> items_;
    std::map<TcpKey, std::list<TcpConversation>::iterator> current_;
};
} // namespace etherscope
