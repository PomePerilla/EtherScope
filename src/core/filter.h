#pragma once
#include "core/packet.h"
#include <string_view>

namespace etherscope {
enum class Direction { Either, Source, Destination };
struct FilterSpec {
    bool operator==(const FilterSpec &) const = default;
    std::optional<std::array<std::uint8_t, 6>> mac;
    std::optional<std::array<std::uint8_t, 4>> ip;
    std::optional<std::array<std::uint8_t, 16>> ipv6;
    Direction macDirection{Direction::Either}, ipDirection{Direction::Either};
    std::string protocol;
    std::optional<std::uint8_t> icmpType;
    std::optional<std::uint64_t> tcpConversationId;
    bool matches(const Packet &packet) const;
};
struct FilterResult {
    std::optional<FilterSpec> value;
    std::string error;
};
FilterResult parseFilter(std::string_view mac, Direction macDirection, std::string_view ip,
                         Direction ipDirection, std::string_view protocol = {},
                         std::optional<std::uint8_t> icmpType = {});
} // namespace etherscope
