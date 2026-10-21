#include "core/packet.h"
#include "core/bytes.h"
#include <algorithm>
#include <charconv>
#include <span>

namespace etherscope {
namespace {
std::string hex(std::uint64_t value, int width = 2) {
    std::array<char, 16> digits{};
    const auto end = std::to_chars(digits.data(), digits.data() + digits.size(), value, 16).ptr;
    for (auto *digit = digits.data(); digit != end; ++digit) {
        if (*digit >= 'a' && *digit <= 'f')
            *digit = static_cast<char>(*digit - 'a' + 'A');
    }
    const auto length = static_cast<std::size_t>(end - digits.data());
    std::string result("0x");
    if (width > 0 && static_cast<std::size_t>(width) > length)
        result.append(static_cast<std::size_t>(width) - length, '0');
    result.append(digits.data(), length);
    return result;
}
struct Decoder {
    Packet p;
    std::span<const std::uint8_t> b;
    explicit Decoder(const RawPacket &raw, bool full) : b(raw.bytes), full_(full) {
        p.raw.timestampNs = raw.timestampNs;
        p.raw.linkType = raw.linkType;
        p.raw.originalLength = raw.originalLength;
        p.raw.interfaceId = raw.interfaceId;
        p.raw.timestampValid = raw.timestampValid;
        p.raw.interfaceInfo = raw.interfaceInfo;
        if (full_)
            root_.field.emplace();
    }
    bool has(std::size_t offset, std::size_t n, std::size_t end) const {
        return end <= b.size() && containsBytes(end, offset, n);
    }
    std::uint16_t u16(std::size_t o) const {
        return std::uint16_t((b[o] << 8) | b[o + 1]);
    }
    std::uint32_t u32(std::size_t o) const {
        return (std::uint32_t(b[o]) << 24) | (std::uint32_t(b[o + 1]) << 16) |
               (std::uint32_t(b[o + 2]) << 8) | b[o + 3];
    }
    template <std::size_t N> std::array<std::uint8_t, N> address(std::size_t o) const {
        std::array<std::uint8_t, N> a{};
        std::copy_n(b.begin() + o, N, a.begin());
        return a;
    }
    void fail(const std::string &message) {
        if (p.error.empty())
            p.error = message;
    }
    std::size_t fieldCount_{};
    bool fieldsLimited_{};
    struct Node {
        std::optional<Field> field;
        std::size_t nodes{1}, lastChildNodes{};
    };
    bool full_{};
    Node root_;
    template <class Factory> Node node(Factory factory) {
        Node result;
        if (full_)
            result.field = factory();
        return result;
    }
    void append(Node &parent, Node value) {
        if (fieldCount_ >= maxPacketFields) {
            if (!fieldsLimited_) {
                fieldsLimited_ = true;
                p.warnings.push_back("字段上限");
            }
            if (value.nodes == 1)
                return;
            fieldCount_ -= value.lastChildNodes;
            value.nodes -= value.lastChildNodes;
            if (full_)
                value.field->children.pop_back();
        }
        ++fieldCount_;
        parent.nodes += value.nodes;
        parent.lastChildNodes = value.nodes;
        if (full_)
            parent.field->children.push_back(std::move(*value.field));
    }
    template <class Factory> void emitField(Node &parent, Factory factory) {
        append(parent, node(factory));
    }
    ChecksumResult checksum(std::size_t o, std::size_t end, std::size_t check) const {
        std::uint32_t sum = 0;
        for (auto cursor = o; cursor < end; cursor += 2) {
            if (cursor == check)
                continue;
            sum += (std::uint32_t(b[cursor]) << 8) | (cursor + 1 < end ? b[cursor + 1] : 0);
        }
        auto fold = [](std::uint32_t value) {
            while (value >> 16)
                value = (value & 65535) + (value >> 16);
            return value;
        };
        sum = fold(sum);
        return {fold(sum + u16(check)) == 65535 ? ChecksumStatus::Match : ChecksumStatus::Mismatch,
                static_cast<std::uint16_t>(~sum)};
    }
    void checksumField(Node &group, const std::string &name, std::size_t o,
                       const ChecksumResult &result) {
        auto field = node([&] { return Field{name, hex(u16(o), 4), o, 2, {}}; });
        emitField(field, [&] {
            return Field{"校验状态",
                         result.status == ChecksumStatus::Match
                             ? "一致"
                             : (result.status == ChecksumStatus::Mismatch ? "不一致" : "未校验"),
                         o,
                         2,
                         {}};
        });
        if (result.computed)
            emitField(field, [&] { return Field{"计算值", hex(*result.computed, 4), o, 2, {}}; });
        append(group, std::move(field));
    }
#include "decode/ipv4_options.inc"
#include "decode/transport.inc"
#include "decode/ipv4.inc"
#include "decode/ipv6.inc"
#include "decode/link.inc"
};
} // namespace
std::string formatMac(const std::array<std::uint8_t, 6> &a) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string result(17, ':');
    for (std::size_t i = 0; i < a.size(); ++i) {
        result[i * 3] = digits[a[i] >> 4];
        result[i * 3 + 1] = digits[a[i] & 15];
    }
    return result;
}
std::string formatIp(const std::array<std::uint8_t, 4> &a) {
    std::array<char, 15> buffer{};
    auto *out = buffer.data();
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (i)
            *out++ = '.';
        out = std::to_chars(out, buffer.data() + buffer.size(), a[i]).ptr;
    }
    return {buffer.data(), static_cast<std::size_t>(out - buffer.data())};
}
std::string formatIpv6(const std::array<std::uint8_t, 16> &a) {
    std::array<unsigned, 8> words{};
    for (std::size_t i = 0; i < 8; ++i)
        words[i] = (unsigned(a[2 * i]) << 8) | a[2 * i + 1];
    std::size_t best = 8, length = 0;
    for (std::size_t i = 0; i < 8;) {
        if (words[i]) {
            ++i;
            continue;
        }
        const auto start = i;
        while (i < 8 && words[i] == 0)
            ++i;
        if (i - start >= 2 && i - start > length) {
            best = start;
            length = i - start;
        }
    }
    std::array<char, 39> buffer{};
    auto *out = buffer.data();
    for (std::size_t i = 0; i < 8;) {
        if (i == best) {
            *out++ = ':';
            *out++ = ':';
            i += length;
        } else {
            if (i > 0 && i != best + length)
                *out++ = ':';
            out = std::to_chars(out, buffer.data() + buffer.size(), words[i++], 16).ptr;
        }
    }
    return {buffer.data(), static_cast<std::size_t>(out - buffer.data())};
}
namespace {
std::size_t stringBytes(const std::string &value) {
    const auto data = reinterpret_cast<std::uintptr_t>(value.data()),
               object = reinterpret_cast<std::uintptr_t>(&value);
    return data >= object && data < object + sizeof(value) ? std::size_t(0) : value.capacity() + 1;
}
std::size_t fieldsBytes(const std::vector<Field> &fields) {
    std::size_t total = fields.capacity() * sizeof(Field);
    for (const auto &field : fields)
        total += stringBytes(field.name) + stringBytes(field.value) + fieldsBytes(field.children);
    return total;
}
} // namespace
std::size_t estimatePacketBytes(const Packet &packet) {
    std::size_t total = sizeof(Packet) + 32 + packet.raw.bytes.capacity() +
                        packet.warnings.capacity() * sizeof(std::string);
    for (const auto *value :
         {&packet.protocol, &packet.source, &packet.destination, &packet.summary, &packet.error})
        total += stringBytes(*value);
    for (const auto &warning : packet.warnings)
        total += stringBytes(warning);
    return total + fieldsBytes(packet.fields);
}
namespace {
Packet decode(RawPacket raw, bool full) {
    Decoder decoder(raw, full);
    auto packet = decoder.run();
    packet.raw = std::move(raw);
    if (full)
        packet.fields = std::move(decoder.root_.field->children);
    packet.estimatedBytes = estimatePacketBytes(packet);
    return packet;
}
} // namespace
Packet decodePacket(RawPacket raw) {
    return decode(std::move(raw), true);
}
Packet decodeSummary(RawPacket raw) {
    return decode(std::move(raw), false);
}
PacketDetails decodeDetails(const RawPacket &raw) {
    Decoder decoder(raw, true);
    auto metadata = decoder.run();
    metadata.fields = std::move(decoder.root_.field->children);
    const auto bytes = fieldsBytes(metadata.fields);
    return {std::move(metadata.fields), sizeof(PacketDetails) + bytes};
}
} // namespace etherscope
