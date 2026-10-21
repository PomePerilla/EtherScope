#pragma once
#include "core/packet.h"
#include <tuple>

namespace etherscope::testing {
inline bool sameSummary(const Packet &a, const Packet &b) {
    auto values = [](const Packet &p) {
        return std::tie(p.protocol, p.source, p.destination, p.summary, p.error, p.warnings,
                        p.sourceMac, p.destinationMac, p.sourceIp, p.destinationIp, p.sourceIpv6,
                        p.destinationIpv6, p.icmpType, p.ipv4Checksum, p.icmpChecksum, p.tcp, p.udp,
                        p.vlanId);
    };
    return values(a) == values(b);
}
inline bool validFields(const std::vector<Field> &fields, std::size_t size, std::size_t &count) {
    for (const auto &field : fields) {
        if (++count > maxPacketFields || field.offset > size ||
            field.length > size - field.offset || !validFields(field.children, size, count))
            return false;
    }
    return true;
}
} // namespace etherscope::testing
