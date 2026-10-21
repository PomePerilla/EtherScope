#pragma once
#include "core/tcp_stream.h"
#include <algorithm>

namespace etherscope::detail {
inline std::optional<std::int64_t> sequenceDistance(std::uint32_t value, std::uint32_t anchor) {
    const auto difference = std::uint32_t(value - anchor);
    if (difference == 0x80000000u)
        return {};
    return difference < 0x80000000u ? std::int64_t(difference)
                                    : std::int64_t(difference) - 0x100000000LL;
}
inline bool sameEndpoint(const Packet &packet, const TcpEndpoint &expected, bool source) {
    if (!packet.tcp ||
        (source ? packet.tcp->sourcePort : packet.tcp->destinationPort) != expected.port)
        return false;
    if (expected.ipv6) {
        const auto &address = source ? packet.sourceIpv6 : packet.destinationIpv6;
        return address && *address == expected.address;
    }
    const auto &address = source ? packet.sourceIp : packet.destinationIp;
    return address && std::equal(address->begin(), address->end(), expected.address.begin());
}
inline std::optional<unsigned> streamDirection(const Packet &packet, const TcpKey &key) {
    if (packet.vlanId != key.vlan || packet.raw.interfaceId != key.interfaceId)
        return {};
    if (sameEndpoint(packet, key.a, true) && sameEndpoint(packet, key.b, false))
        return 0;
    if (sameEndpoint(packet, key.b, true) && sameEndpoint(packet, key.a, false))
        return 1;
    return {};
}
} // namespace etherscope::detail
