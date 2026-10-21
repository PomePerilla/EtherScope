#include "core/filter.h"
#include <algorithm>
#include <charconv>
#include <cctype>

namespace etherscope {
namespace {
std::string trim(std::string_view input) {
    while (!input.empty() && std::isspace(static_cast<unsigned char>(input.front())))
        input.remove_prefix(1);
    while (!input.empty() && std::isspace(static_cast<unsigned char>(input.back())))
        input.remove_suffix(1);
    return std::string(input);
}
template <std::size_t N>
bool match(const std::optional<std::array<std::uint8_t, N>> &expected, Direction dir,
           const std::optional<std::array<std::uint8_t, N>> &src,
           const std::optional<std::array<std::uint8_t, N>> &dst) {
    if (!expected)
        return true;
    const bool a = src && *src == *expected, b = dst && *dst == *expected;
    return dir == Direction::Source ? a : (dir == Direction::Destination ? b : a || b);
}
std::optional<std::array<std::uint8_t, 4>> ipv4Address(std::string_view ip) {
    std::array<std::uint8_t, 4> address{};
    std::size_t start = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        auto end = ip.find('.', start);
        if (end == std::string_view::npos)
            end = ip.size();
        if (end == start || (i < 3 && end == ip.size()) || (i == 3 && end != ip.size()))
            return {};
        unsigned value = 0;
        auto r = std::from_chars(ip.data() + start, ip.data() + end, value, 10);
        if (r.ec != std::errc{} || r.ptr != ip.data() + end || value > 255)
            return {};
        address[i] = static_cast<std::uint8_t>(value);
        start = end + 1;
    }
    return address;
}
std::optional<std::array<std::uint8_t, 16>> ipv6Address(std::string text) {
    if (text.find_first_of("%/[]") != std::string::npos || text.size() > 45)
        return {};
    // A dotted IPv4 tail occupies two hextets, including in mapped addresses.
    if (text.find('.') != std::string::npos) {
        const auto colon = text.rfind(':');
        if (colon == std::string::npos)
            return {};
        auto tail = ipv4Address(std::string_view(text).substr(colon + 1));
        if (!tail)
            return {};
        static constexpr char digits[] = "0123456789abcdef";
        std::string words;
        for (std::size_t i = 0; i < 4; ++i) {
            if (i == 2)
                words += ':';
            words += digits[(*tail)[i] >> 4];
            words += digits[(*tail)[i] & 15];
        }
        text = text.substr(0, colon + 1) + words;
    }
    const auto compressed = text.find("::");
    if (compressed != std::string::npos && text.find("::", compressed + 2) != std::string::npos)
        return {};
    auto read = [](std::string_view side, std::vector<std::uint16_t> &words) {
        if (side.empty())
            return true;
        while (!side.empty()) {
            const auto colon = side.find(':');
            const auto word = side.substr(0, colon);
            if (word.empty() || word.size() > 4 || words.size() >= 8)
                return false;
            unsigned value = 0;
            auto r = std::from_chars(word.data(), word.data() + word.size(), value, 16);
            if (r.ec != std::errc{} || r.ptr != word.data() + word.size() || value > 65535)
                return false;
            words.push_back(static_cast<std::uint16_t>(value));
            if (colon == std::string_view::npos)
                return true;
            side.remove_prefix(colon + 1);
            if (side.empty())
                return false;
        }
        return true;
    };
    std::vector<std::uint16_t> left, right;
    if (compressed == std::string::npos) {
        if (!read(text, left) || left.size() != 8)
            return {};
    } else if (!read(std::string_view(text).substr(0, compressed), left) ||
               !read(std::string_view(text).substr(compressed + 2), right) ||
               left.size() + right.size() >= 8)
        return {};
    std::array<std::uint8_t, 16> address{};
    auto put = [&](std::size_t i, std::uint16_t word) {
        address[2 * i] = std::uint8_t(word >> 8);
        address[2 * i + 1] = std::uint8_t(word);
    };
    for (std::size_t i = 0; i < left.size(); ++i)
        put(i, left[i]);
    for (std::size_t i = 0; i < right.size(); ++i)
        put(8 - right.size() + i, right[i]);
    return address;
}
} // namespace
bool FilterSpec::matches(const Packet &p) const {
    const bool family = (protocol == "IPv6" && p.sourceIpv6.has_value()) ||
                        (protocol == "IPv4" && p.sourceIp.has_value());
    const bool layer = protocol == "Ethernet"
                           ? (p.raw.linkType == 1 && p.sourceMac && p.destinationMac)
                           : (protocol.empty() || protocol == p.protocol || family);
    return match(mac, macDirection, p.sourceMac, p.destinationMac) &&
           match(ip, ipDirection, p.sourceIp, p.destinationIp) &&
           match(ipv6, ipDirection, p.sourceIpv6, p.destinationIpv6) && layer &&
           (!icmpType || (protocol == "ICMP" && p.icmpType == icmpType)) &&
           (!tcpConversationId || p.tcpConversationId == *tcpConversationId);
}
FilterResult parseFilter(std::string_view macText, Direction macDir, std::string_view ipText,
                         Direction ipDir, std::string_view protocolText,
                         std::optional<std::uint8_t> icmpType) {
    FilterSpec f;
    f.macDirection = macDir;
    f.ipDirection = ipDir;
    const auto mac = trim(macText), ip = trim(ipText);
    f.protocol = trim(protocolText);
    if (!mac.empty()) {
        if (mac.size() != 17 || (mac[2] != ':' && mac[2] != '-'))
            return {{}, "MAC 地址无效"};
        std::array<std::uint8_t, 6> a{};
        for (std::size_t i = 0; i < 6; ++i) {
            unsigned value = 0;
            auto first = mac.data() + i * 3;
            auto r = std::from_chars(first, first + 2, value, 16);
            if (r.ec != std::errc{} || r.ptr != first + 2 || (i < 5 && mac[i * 3 + 2] != mac[2]))
                return {{}, "MAC 地址无效"};
            a[i] = static_cast<std::uint8_t>(value);
        }
        f.mac = a;
    }
    if (!ip.empty()) {
        if (ip.find(':') != std::string::npos) {
            f.ipv6 = ipv6Address(ip);
            if (!f.ipv6)
                return {{}, "IPv6 地址无效"};
        } else {
            f.ip = ipv4Address(ip);
            if (!f.ip)
                return {{}, "IPv4 地址无效"};
        }
    }
    static const std::array<std::string_view, 9> protocols = {
        "", "Ethernet", "IPv4", "ICMP", "ARP", "TCP", "UDP", "IPv6", "ICMPv6"};
    if (std::find(protocols.begin(), protocols.end(), f.protocol) == protocols.end())
        return {{}, "未知协议过滤条件"};
    if (icmpType && (f.protocol != "ICMP" ||
                     (*icmpType != 8 && *icmpType != 0 && *icmpType != 11 && *icmpType != 3)))
        return {{}, "ICMP 类型无效"};
    f.icmpType = icmpType;
    return {f, {}};
}
} // namespace etherscope
