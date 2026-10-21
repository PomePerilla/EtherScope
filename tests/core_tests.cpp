#include "fixtures.h"
#include <algorithm>
#include "parser_invariants.h"
#include "core/filter.h"
#include "core/pcap_file.h"
#include "core/session.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <locale>
#include <random>
#include <sstream>
#include <stdexcept>

using namespace etherscope;
namespace {
int checks = 0;
void require(bool value, const std::string &message) {
    ++checks;
    if (!value)
        throw std::runtime_error(message);
}
const Field *find(const std::vector<Field> &fields, const std::string &name) {
    for (const auto &f : fields) {
        if (f.name == name)
            return &f;
        if (auto *c = find(f.children, name))
            return c;
    }
    return nullptr;
}
void bounds(const std::vector<Field> &fields, std::size_t length) {
    for (const auto &f : fields) {
        require(f.offset <= length && f.length <= length - f.offset,
                "Field byte range outside captured bytes: " + f.name);
        bounds(f.children, length);
    }
}
std::string serialize(const std::vector<Packet> &packets) {
    std::vector<const Packet *> ptrs;
    for (const auto &p : packets)
        ptrs.push_back(&p);
    std::ostringstream stream(std::ios::binary);
    writePcap(stream, ptrs);
    return stream.str();
}
struct TempFile {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() /
        ("etherscope-test-" + std::to_string(std::random_device{}()) + ".pcap");
    void write(const std::string &bytes) {
        std::ofstream out(path, std::ios::binary);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
};
bool rejects(const std::string &bytes) {
    TempFile file;
    file.write(bytes);
    try {
        PcapReader r(file.path);
        while (r.next()) {
        }
        return false;
    } catch (const std::exception &) {
        return true;
    }
}
void addressFormatting() {
    require(formatMac({0, 1, 15, 16, 171, 255}) == "00:01:0F:10:AB:FF", "Canonical MAC text");
    require(formatIp({255, 255, 255, 255}) == "255.255.255.255", "Maximum-width IPv4 text");
    std::mt19937 random(20261020);
    for (int i = 0; i < 1000; ++i) {
        std::array<std::uint8_t, 6> mac{};
        for (auto &byte : mac)
            byte = static_cast<std::uint8_t>(random());
        std::array<std::uint8_t, 4> ip{};
        for (auto &byte : ip)
            byte = static_cast<std::uint8_t>(random());
        std::array<std::uint8_t, 16> ipv6{};
        for (std::size_t j = 0; j < ipv6.size(); j += 2) {
            const auto word = random() % 3 == 0 ? 0 : random() & 0xffff;
            ipv6[j] = static_cast<std::uint8_t>(word >> 8);
            ipv6[j + 1] = static_cast<std::uint8_t>(word);
        }
        auto parsedMac = parseFilter(formatMac(mac), Direction::Either, "", Direction::Either);
        require(parsedMac.value && parsedMac.value->mac == mac, "MAC text roundtrip");
        auto parsedIp = parseFilter("", Direction::Either, formatIp(ip), Direction::Either);
        require(parsedIp.value && parsedIp.value->ip == ip, "IPv4 text roundtrip");
        auto parsedIpv6 = parseFilter("", Direction::Either, formatIpv6(ipv6), Direction::Either);
        require(parsedIpv6.value && parsedIpv6.value->ipv6 == ipv6, "IPv6 text roundtrip");
    }
    class GroupedNumbers final : public std::numpunct<char> {
        char do_thousands_sep() const override {
            return ',';
        }
        std::string do_grouping() const override {
            return "\3";
        }
    };
    struct LocaleGuard {
        std::locale previous = std::locale();
        ~LocaleGuard() {
            std::locale::global(previous);
        }
    } guard;
    const auto address =
        *parseFilter("", Direction::Either, "ffff:abcd:1234::ffff", Direction::Either).value->ipv6;
    std::locale::global(std::locale(guard.previous, new GroupedNumbers));
    require(formatIpv6(address) == "ffff:abcd:1234::ffff",
            "IPv6 text is independent of global numeric locale");
    require(formatMac({255, 171, 18, 0, 1, 254}) == "FF:AB:12:00:01:FE",
            "MAC text is independent of global numeric locale");
}
void pcapWireEncoding() {
    Packet packet;
    packet.raw = {2123456789LL, 1, 5, {0x11, 0x22, 0x33}};
    const std::string expected("\x4d\x3c\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                               "\xff\xff\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x15\xcd\x5b\x07"
                               "\x03\x00\x00\x00\x05\x00\x00\x00\x11\x22\x33",
                               43);
    require(serialize({packet}) == expected, "Exact nanosecond PCAP header and record bytes");
}
void protocols() {
    auto raws = fixtures::samples();
    std::vector<Packet> packets;
    for (auto r : raws)
        packets.push_back(decodePacket(std::move(r)));
    for (std::size_t i = 0; i < packets.size(); ++i) {
        if (i != 11)
            require(packets[i].error.empty(), "Unexpected decode error " + std::to_string(i));
        bounds(packets[i].fields, packets[i].raw.bytes.size());
    }
    require(packets[0].protocol == "ICMP" &&
                packets[0].summary.find("回显请求") != std::string::npos,
            "Echo request");
    require(packets[1].summary.find("回显应答") != std::string::npos, "Echo reply");
    require(packets[2].summary.find("时间超过") != std::string::npos, "Time exceeded");
    require(packets[3].summary.find("目的地址不可达") != std::string::npos, "Unreachable");
    require(find(packets[3].fields, "原因")->value == "端口不可达", "ICMP code");
    require(find(packets[0].fields, "序列号")->offset == 40, "ICMP sequence offset");
    require(find(packets[7].fields, "序列号")->offset == 44, "IPv4 options change ICMP offset");
    require(find(packets[8].fields, "VLAN ID")->value == "42", "VLAN ID");
    require(find(packets[8].fields, "序列号")->offset == 44, "VLAN changes network offset");
    require(packets[4].protocol == "ARP" &&
                find(packets[4].fields, "发送者 IP")->value == "192.0.2.1",
            "ARP addresses");
    require(packets[5].protocol == "TCP" && find(packets[5].fields, "源端口")->value == "12345",
            "TCP port");
    require(find(find(packets[5].fields, "TCP")->children, "标志")->value.find("SYN") !=
                std::string::npos,
            "TCP flags");
    require(find(packets[5].fields, "选项")->length == 4, "TCP options");
    require(packets[6].protocol == "UDP" && find(packets[6].fields, "长度")->value == "12",
            "UDP length");
    require(packets[9].protocol == "IPv4" && !find(packets[9].fields, "ICMP"),
            "Nonfirst fragment must not decode transport");
    require(!packets[9].warnings.empty(), "Fragment warning");
    require(packets[10].protocol == "Ethernet", "Unknown EtherType retained");
    require(!packets[11].error.empty(), "Truncated capture error");
    require(find(packets[0].fields, "FCS")->length == 0, "Never fabricate FCS");
    auto invalid = fixtures::icmp();
    invalid.bytes[14] = 0x44;
    require(!decodePacket(invalid).error.empty(), "Invalid IHL");
    invalid = fixtures::icmp();
    invalid.bytes[16] = 0;
    invalid.bytes[17] = 10;
    require(!decodePacket(invalid).error.empty(), "Total length smaller than header");
    invalid = fixtures::icmp();
    invalid.linkType = 113;
    require(decodePacket(invalid).fields.empty(), "Reject non-Ethernet link");
    invalid = raws[6];
    invalid.bytes[38] = 0;
    invalid.bytes[39] = 7;
    require(!decodePacket(invalid).error.empty(), "UDP length below minimum");
    auto frag = fixtures::ipv4(17, {0, 1, 0, 2, 0, 40, 0, 0}, false, 0x2000);
    require(decodePacket(frag).error.empty(),
            "First UDP fragment can announce larger full UDP length");
    std::mt19937 rng(20261016);
    for (const auto &raw : raws)
        for (std::size_t n = 0; n < raw.bytes.size(); ++n) {
            auto shortRaw = raw;
            shortRaw.bytes.resize(n);
            auto p = decodePacket(shortRaw);
            bounds(p.fields, n);
        }
    for (int i = 0; i < 5000; ++i) {
        RawPacket r;
        r.bytes.resize(rng() % 300);
        for (auto &x : r.bytes)
            x = std::uint8_t(rng());
        r.originalLength = static_cast<std::uint32_t>(r.bytes.size());
        auto p = decodePacket(std::move(r));
        bounds(p.fields, p.raw.bytes.size());
    }
    for (int i = 0; i < 2000; ++i) {
        auto r = raws[rng() % raws.size()];
        if (!r.bytes.empty())
            r.bytes[rng() % r.bytes.size()] = std::uint8_t(rng());
        auto p = decodePacket(std::move(r));
        bounds(p.fields, p.raw.bytes.size());
    }
}
void analysis() {
    auto raws = fixtures::analysisSamples();
    std::vector<Packet> packets;
    for (auto raw : raws) {
        packets.push_back(decodePacket(std::move(raw)));
        bounds(packets.back().fields, packets.back().raw.bytes.size());
    }
    for (std::size_t i = 0; i < 12; ++i)
        require(packets[i].error.empty(),
                "Analysis fixture " + std::to_string(i) + ": " + packets[i].error);
    require(find(packets[0].fields, "EOL") && find(packets[0].fields, "NOP"),
            "EOL/NOP option nodes");
    require(find(packets[1].fields, "地址 1")->value == "192.0.2.254" &&
                find(packets[1].fields, "地址 1")->offset == 37,
            "RR address and byte range");
    for (auto i : {2, 3})
        require(find(packets[i].fields, "时间戳 1")->value == "42", "Timestamp formats 0/1");
    require(find(packets[4].fields, "格式")->value == "3" &&
                find(packets[4].fields, "指针")->value == "5",
            "Prespecified timestamp");
    require(find(packets[5].fields, "未知选项")->length == 4 &&
                find(packets[5].fields, "数据")->offset == 36,
            "Unknown IPv4 option range");
    require(packets[6].ipv4Checksum.status == ChecksumStatus::Mismatch &&
                packets[6].icmpChecksum.status == ChecksumStatus::Match &&
                packets[6].warnings.empty(),
            "Header mismatch independent of parse status");
    require(packets[7].icmpChecksum.status == ChecksumStatus::Mismatch &&
                packets[7].ipv4Checksum.status == ChecksumStatus::Match &&
                packets[7].warnings.empty(),
            "ICMP mismatch independent of parse status");
    require(packets[8].icmpChecksum.status == ChecksumStatus::Match &&
                packets[8].icmpChecksum.computed == 0xf6ff,
            "Fixed odd-byte checksum vector");
    require(packets[9].icmpChecksum.status == ChecksumStatus::Match &&
                packets[9].icmpChecksum.computed == 0,
            "Computed zero is a valid checksum");
    auto negativeZero = raws[9];
    negativeZero.bytes[36] = negativeZero.bytes[37] = 255;
    require(decodePacket(negativeZero).icmpChecksum.status == ChecksumStatus::Match,
            "One's-complement zero equivalence");
    for (auto i : {10, 11})
        require(find(packets[i].fields, "TCP")->value == "不完整首部" &&
                    !packets[i].warnings.empty(),
                "First TCP fragment is incomplete, not malformed");
    require(!packets[12].error.empty() &&
                packets[12].ipv4Checksum.status == ChecksumStatus::Match &&
                packets[12].icmpChecksum.status == ChecksumStatus::NotChecked,
            "Truncated payload still validates IPv4 header");
    require(packets[13].error.empty() &&
                packets[13].icmpChecksum.status == ChecksumStatus::NotChecked &&
                !packets[13].icmpChecksum.computed,
            "Fragmented ICMP not checked");
    for (std::size_t i = 14; i < raws.size(); ++i)
        require(!packets[i].error.empty(), "Reject malformed option " + std::to_string(i));
    auto padded = raws[8];
    padded.bytes.resize(100, 0xaa);
    padded.originalLength = 100;
    require(decodePacket(padded).icmpChecksum.status == ChecksumStatus::Match,
            "Ethernet padding excluded from ICMP checksum");
    auto tiny = fixtures::icmp();
    tiny.bytes.resize(37);
    auto shortPacket = decodePacket(tiny);
    require(shortPacket.icmpType == 8 &&
                shortPacket.icmpChecksum.status == ChecksumStatus::NotChecked,
            "Truncated common header retains known type");
    auto invalidTcp = raws[11];
    invalidTcp.bytes[46] = 0x40;
    require(!decodePacket(invalidTcp).error.empty(),
            "Invalid TCP offset still fails on a first fragment");
    auto cutTcp = raws[11];
    cutTcp.bytes.pop_back();
    require(!decodePacket(cutTcp).error.empty(), "True truncated TCP fragment still fails");
    auto nonfirst = raws[10];
    nonfirst.bytes[20] = 0;
    nonfirst.bytes[21] = 1;
    auto rest = decodePacket(nonfirst);
    require(rest.protocol == "IPv4" && !find(rest.fields, "TCP"),
            "Nonfirst TCP fragment never decoded as header");
    auto end = fixtures::ipv4Options({0, 0xff, 0xff, 0xff});
    require(decodePacket(end).error.empty(), "EOL terminates option parsing");
    for (const auto &options : std::vector<std::vector<std::uint8_t>>{{1, 1, 1, 0x9e},
                                                                      {0x9e, 0, 0, 0},
                                                                      {7, 2, 0, 0},
                                                                      {68, 3, 0, 0},
                                                                      {68, 8, 6, 0, 0, 0, 0, 0},
                                                                      {68, 8, 10, 0, 0, 0, 0, 0}})
        require(!decodePacket(fixtures::ipv4Options(options)).error.empty(),
                "Malformed option length or pointer");
    for (const auto &raw : raws)
        for (std::size_t n = 0; n < raw.bytes.size(); ++n) {
            auto cut = raw;
            cut.bytes.resize(n);
            auto decoded = decodePacket(std::move(cut));
            bounds(decoded.fields, n);
        }
    for (std::size_t i = 0; i < raws.size(); ++i)
        require(packets[i].raw.bytes == raws[i].bytes, "Analysis preserves raw packet");
    auto layer = parseFilter("", Direction::Either, "", Direction::Either, "Ethernet");
    for (auto raw : fixtures::samples()) {
        auto p = decodePacket(std::move(raw));
        require(layer.value->matches(p), "Ethernet filter includes all upper layers");
    }
    for (auto raw : fixtures::ipv6Samples())
        require(layer.value->matches(decodePacket(std::move(raw))),
                "Ethernet filter includes IPv6");
    RawPacket noHeader;
    noHeader.bytes.resize(13);
    noHeader.originalLength = 13;
    require(!layer.value->matches(decodePacket(noHeader)), "Incomplete Ethernet header excluded");
    for (auto type : {8, 0, 11, 3}) {
        auto f = parseFilter("", Direction::Either, "", Direction::Either, "ICMP",
                             static_cast<std::uint8_t>(type));
        require(f.value.has_value(), "ICMP subtype accepted");
        for (auto other : {8, 0, 11, 3})
            require(f.value->matches(decodePacket(
                        fixtures::icmp(static_cast<std::uint8_t>(other)))) == (type == other),
                    "Subtype matches exact ICMP type");
    }
    require(
        !parseFilter("", Direction::Either, "", Direction::Either, "ICMP", std::uint8_t(13)).value,
        "Unsupported ICMP subtype rejected");
    require(
        !parseFilter("", Direction::Either, "", Direction::Either, "UDP", std::uint8_t(8)).value,
        "Subtype requires ICMP");
    auto combined = parseFilter("02:00:00:00:00:01", Direction::Source, "192.0.2.2",
                                Direction::Destination, "ICMP", std::uint8_t(8));
    require(combined.value->matches(decodePacket(fixtures::icmp())) &&
                !combined.value->matches(decodePacket(fixtures::icmp(0))),
            "MAC/IP/subtype intersection");
}
void filters() {
    auto p = decodePacket(fixtures::icmp());
    require(parseFilter("", Direction::Either, "", Direction::Either).value->matches(p),
            "Empty filter");
    auto f = parseFilter("02-00-00-00-00-01", Direction::Source, "192.0.2.2",
                         Direction::Destination, "ICMP");
    require(f.value && f.value->matches(p), "MAC/IP AND with explicit directions");
    require(!parseFilter("02:00:00:00:00:02", Direction::Source, "", Direction::Either)
                 .value->matches(p),
            "Wrong source MAC");
    require(parseFilter("02:00:00:00:00:02", Direction::Either, "192.0.2.1", Direction::Either)
                .value->matches(p),
            "Either direction");
    require(
        !parseFilter("", Direction::Either, "192.0.2.1", Direction::Destination).value->matches(p),
        "Wrong destination IP");
    require(!parseFilter("", Direction::Either, "", Direction::Either, "UDP").value->matches(p),
            "Protocol filter");
    for (const auto &ip : {"1.2.3", "1.2.3.4.5", "256.0.0.1", "-1.2.3.4", "1..2.3", "1.2.3.4x"})
        require(!parseFilter("", Direction::Either, ip, Direction::Either).value, "Invalid IP");
    for (const auto &mac :
         {"01:02:03", "GG:00:00:00:00:00", "01:02-03:04:05:06", "+1:00:00:00:00:00"})
        require(!parseFilter(mac, Direction::Either, "", Direction::Either).value, "Invalid MAC");
    auto arp = decodePacket(fixtures::samples()[4]);
    require(!parseFilter("", Direction::Either, "192.0.2.1", Direction::Either).value->matches(arp),
            "IPv4 filter does not confuse ARP payload with IPv4 header");
}
void ipv6() {
    auto raws = fixtures::ipv6Samples();
    std::vector<Packet> packets;
    for (auto raw : raws) {
        auto p = decodePacket(std::move(raw));
        require(p.error.empty(), "IPv6 fixture: " + p.error);
        bounds(p.fields, p.raw.bytes.size());
        require(p.sourceIpv6 && !p.sourceIp, "Separate IPv6 addresses");
        packets.push_back(std::move(p));
    }
    require(packets[0].source == "2001:db8::1" && packets[0].destination == "2001:db8::2",
            "Compressed IPv6 addresses");
    require(find(packets[0].fields, "流标签")->value == "0x12345" &&
                find(packets[0].fields, "流量类别")->value == "46",
            "IPv6 bit fields");
    require(packets[0].protocol == "ICMPv6" && find(packets[0].fields, "序列号")->offset == 60,
            "ICMPv6 echo fields");
    require(packets[2].protocol == "TCP" && packets[3].protocol == "UDP",
            "IPv6 transport dispatch");
    require(find(packets[4].fields, "UDP")->offset == 78, "Extension chain locates UDP");
    require(packets[5].protocol == "UDP" && !packets[5].warnings.empty(),
            "First fragment transport");
    require(packets[6].protocol == "IPv6" && !find(packets[6].fields, "TCP"),
            "Nonfirst IPv6 fragment never decodes fake TCP");
    require(packets[7].protocol == "UDP" && packets[7].warnings.empty(), "Atomic fragment");
    require(find(packets[8].fields, "TCP")->offset == 78 &&
                find(packets[8].fields, "SPI")->value == "0x00000007",
            "AH length uses 32-bit units");
    require(find(packets[9].fields, "ESP") && !find(packets[9].fields, "TCP"), "ESP is opaque");
    require(packets[10].summary.find("无下一首部") != std::string::npos, "No next header");
    require(find(packets[11].fields, "目标地址")->value == "2001:db8::2" &&
                find(packets[11].fields, "源链路地址"),
            "Neighbor solicitation");
    require(find(packets[12].fields, "标志")->value == "R=0 S=1 O=1",
            "Neighbor advertisement flags");
    require(find(packets[14].fields, "MTU")->value == "1500" &&
                find(packets[14].fields, "前缀")->value == "2001:db8::",
            "Router advertisement options");
    require(find(packets[15].fields, "重定向目的地址")->value == "2001:db8::3", "Redirect");
    for (int i = 16; i < 20; ++i)
        require(find(packets[i].fields, "引用的原始 IPv6 首部"), "ICMPv6 errors quote IPv6");
    require(find(packets[20].fields, "ICMPv6")->offset == 58, "VLAN IPv6 offsets");
    for (const auto &text : {"2001:db8::1", "2001:0DB8:0:0:0:0:0:1", "2001:db8:0:0:0:0:0:1"}) {
        auto f = parseFilter("", Direction::Either, text, Direction::Source, "IPv6");
        require(f.value && f.value->matches(packets[0]), "Equivalent IPv6 filters");
        require(!f.value->matches(decodePacket(fixtures::icmp())), "IPv6 filter cannot match IPv4");
    }
    require(parseFilter("02:00:00:00:00:01", Direction::Source, "2001:db8::2",
                        Direction::Destination, "ICMPv6")
                .value->matches(packets[0]),
            "MAC IPv6 AND");
    require(!parseFilter("", Direction::Either, "2001:db8::1", Direction::Destination)
                 .value->matches(packets[0]),
            "IPv6 direction");
    require(parseFilter("", Direction::Either, "", Direction::Either, "IPv6")
                .value->matches(packets[2]),
            "IPv6 protocol filter includes TCP");
    require(parseFilter("", Direction::Either, "", Direction::Either, "IPv4")
                .value->matches(decodePacket(fixtures::icmp())),
            "IPv4 protocol filter includes ICMP");
    for (const auto &text :
         {"::", "::1", "1::", "::ffff:192.0.2.1", "1:2:3:4:5:6:192.0.2.1", "1:2:3:4:5:6:7:8"}) {
        auto f = parseFilter("", Direction::Either, text, Direction::Either);
        require(f.value && f.value->ipv6, "Valid IPv6 literal");
        auto roundtrip =
            parseFilter("", Direction::Either, formatIpv6(*f.value->ipv6), Direction::Either);
        require(roundtrip.value && f.value->ipv6 == roundtrip.value->ipv6, "IPv6 text roundtrip");
    }
    for (const auto &text : {":", ":::1", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
                             "1:2:3:4:5:6:7:8::", "gg::1", "12345::", "fe80::1%12", "2001:db8::/64",
                             "[::1]", "::ffff:300.1.2.3", "192.0.2.1::", "1:2:3:4:5:6:7:8:"})
        require(!parseFilter("", Direction::Either, text, Direction::Either).value,
                "Invalid IPv6 literal");
    auto format = [](const char *text) {
        return formatIpv6(*parseFilter("", Direction::Either, text, Direction::Either).value->ipv6);
    };
    require(format("1:0:0:2:0:0:3:4") == "1::2:0:0:3:4", "Longest zero-run tie chooses first");
    require(format("1:0:2:3:4:5:6:7") == "1:0:2:3:4:5:6:7", "Single zero is not compressed");
    auto invalid = raws[0];
    invalid.bytes[14] = 0x42;
    require(!decodePacket(invalid).error.empty(), "IPv6 wrong version");
    invalid = raws[0];
    invalid.bytes[18] = 0xff;
    require(!decodePacket(invalid).error.empty(), "IPv6 payload truncation");
    invalid = raws[4];
    invalid.bytes[55] = 255;
    require(!decodePacket(invalid).error.empty(), "Extension claims unavailable bytes");
    invalid = raws[4];
    invalid.bytes[57] = 255;
    require(!decodePacket(invalid).error.empty(), "TLV exceeds its header");
    invalid = raws[11];
    invalid.bytes[79] = 0;
    require(!decodePacket(invalid).error.empty(), "Zero ND option length cannot loop");
    invalid = raws[8];
    invalid.bytes[55] = 0;
    require(!decodePacket(invalid).error.empty(), "AH below 12 bytes");
    invalid = raws[0];
    invalid.bytes[18] = invalid.bytes[19] = 0;
    auto jumbo = decodePacket(invalid);
    require(jumbo.protocol == "IPv6" && !jumbo.warnings.empty() && !find(jumbo.fields, "ICMPv6"),
            "Zero-length payload not parsed as jumbo");
    auto padded = raws[0];
    padded.bytes[19] = 4;
    require(!decodePacket(padded).error.empty(),
            "Ethernet padding cannot complete a short ICMPv6 payload");
    std::vector<std::uint8_t> chain;
    for (int i = 0; i < 33; ++i)
        chain.insert(chain.end(), {60, 0, 0, 0, 0, 0, 0, 0});
    require(!decodePacket(fixtures::ipv6(60, chain)).error.empty(), "Extension count bounded");
    for (const auto &raw : raws)
        for (std::size_t n = 0; n < raw.bytes.size(); ++n) {
            auto r = raw;
            r.bytes.resize(n);
            auto p = decodePacket(r);
            bounds(p.fields, n);
        }
    std::mt19937 rng(20261020);
    for (int i = 0; i < 5000; ++i) {
        auto r = raws[rng() % raws.size()];
        r.bytes[rng() % r.bytes.size()] = std::uint8_t(rng());
        auto p = decodePacket(std::move(r));
        bounds(p.fields, p.raw.bytes.size());
    }
    auto serialized = serialize(packets);
    TempFile file;
    file.write(serialized);
    PcapReader reader(file.path);
    for (const auto &p : packets) {
        auto raw = reader.next();
        require(raw && raw->bytes == p.raw.bytes, "IPv6 PCAP preserves bytes");
        require(decodePacket(*raw).protocol == p.protocol, "IPv6 PCAP shared decoder");
    }
}
void pcap() {
    std::vector<Packet> packets;
    for (auto raw : fixtures::samples())
        packets.push_back(decodePacket(std::move(raw)));
    auto bytes = serialize(packets);
    TempFile file;
    file.write(bytes);
    PcapReader r(file.path);
    for (const auto &p : packets) {
        auto read = r.next();
        require(read && read->bytes == p.raw.bytes && read->timestampNs == p.raw.timestampNs &&
                    read->originalLength == p.raw.originalLength,
                "PCAP nanosecond roundtrip");
    }
    require(!r.next(), "EOF");
    require(rejects(bytes.substr(0, 12)), "Truncated global header");
    require(rejects(bytes.substr(0, bytes.size() - 1)), "Truncated last record");
    auto bad = bytes;
    bad[20] = 113;
    require(rejects(bad), "Wrong link type");
    bad = bytes;
    bad[32] = char(-1);
    bad[33] = char(-1);
    bad[34] = char(-1);
    bad[35] = char(127);
    require(rejects(bad), "Oversized caplen");
    bad = bytes;
    bad[36] = 0;
    bad[37] = 0;
    bad[38] = 0;
    bad[39] = 0;
    require(rejects(bad), "origlen < caplen");
    bad = bytes.substr(0, 24);
    bad.push_back(0);
    require(rejects(bad), "Partial record header");
    auto one = serialize({packets[0]});
    one[0] = char(-44);
    one[1] = char(-61);
    one[2] = char(-78);
    one[3] = char(-95);
    const std::uint32_t us = 123456;
    for (int i = 0; i < 4; ++i)
        one[28 + i] = char(us >> (8 * i));
    file.write(one);
    {
        PcapReader micro(file.path);
        require(micro.next()->timestampNs == 1700000000123456000LL, "Microsecond PCAP");
    }
    auto big = one;
    for (std::size_t o : {0u, 8u, 12u, 16u, 20u, 24u, 28u, 32u, 36u})
        std::reverse(big.begin() + o, big.begin() + o + 4);
    std::swap(big[4], big[5]);
    std::swap(big[6], big[7]);
    file.write(big);
    {
        PcapReader be(file.path);
        require(be.next()->bytes == packets[0].raw.bytes, "Big-endian PCAP");
    }
    require(!rejects(serialize({})), "Empty valid PCAP");
}
void resourceBudgets() {
    auto nodes = [](auto &&self, const std::vector<Field> &fields) -> std::size_t {
        std::size_t result = fields.size();
        for (const auto &field : fields)
            result += self(self, field.children);
        return result;
    };
    std::vector<std::uint8_t> options(24, 0);
    options[0] = 135;
    for (int i = 0; i < 8000; ++i)
        options.insert(options.end(), {99, 1, 0, 0, 0, 0, 0, 0});
    const auto raw = fixtures::ipv6(58, options, 255);
    auto dense = decodePacket(raw);
    require(dense.error.empty() && dense.protocol == "ICMPv6", "Dense NDP remains parsed");
    require(nodes(nodes, dense.fields) <= maxPacketFields && nodes(nodes, dense.fields) > 4000,
            "Field nodes bounded while retaining details");
    require(find(dense.fields, "ICMPv6"), "Protocol root retained at field budget");
    require(std::find(dense.warnings.begin(), dense.warnings.end(), "字段上限") !=
                dense.warnings.end(),
            "Budget warning");
    bounds(dense.fields, raw.bytes.size());
    options[options.size() - 7] = 0;
    auto invalid = decodePacket(fixtures::ipv6(58, options, 255));
    require(!invalid.error.empty(), "Validate option lengths beyond node budget");
    std::vector<std::uint8_t> padding(2048, 0);
    padding[0] = 59;
    padding[1] = 255;
    auto padded = decodePacket(fixtures::ipv6(60, padding));
    const auto *pad = find(padded.fields, "Pad1");
    require(pad && pad->length == 2046, "Consecutive Pad1 merged");
    const auto cost = estimatePacketBytes(dense);
    require(cost == dense.estimatedBytes && cost > dense.raw.bytes.size(),
            "Estimated memory includes fields");
    SessionStore limited(10000, 64 * 1024 * 1024, cost * 2);
    for (int i = 0; i < 6; ++i)
        limited.append(decodePacket(raw));
    require(limited.packets().size() == 2 && limited.stats().overwritten == 4,
            "Estimated bytes evict before packet count");
    require(limited.estimatedBytes() <= cost * 2 && limited.packets().front()->id == 5,
            "Budget preserves newest records");
    auto snapshot = limited.packets().front();
    const auto snapshotBytes = snapshot->raw.bytes;
    limited.clear();
    require(limited.estimatedBytes() == 0 && snapshot->raw.bytes == snapshotBytes,
            "Snapshot keeps immutable evicted data");
    SessionStore tiny(10000, 64 * 1024 * 1024, cost - 1);
    tiny.append(decodePacket(raw));
    require(tiny.packets().empty() && tiny.stats().overwritten == 1, "Oversized decoded record");
    auto packet = decodePacket(fixtures::icmp());
    const auto base = estimatePacketBytes(packet);
    packet.summary.reserve(4096);
    require(estimatePacketBytes(packet) > base + 3000, "String capacities included");
}
void summaryModes() {
    auto raws = fixtures::samples();
    for (auto list : {fixtures::ipv6Samples(), fixtures::analysisSamples()})
        raws.insert(raws.end(), list.begin(), list.end());
    std::vector<std::uint8_t> options(24, 0);
    options[0] = 135;
    for (int i = 0; i < 8000; ++i)
        options.insert(options.end(), {99, 1, 0, 0, 0, 0, 0, 0});
    raws.push_back(fixtures::ipv6(58, options, 255));
    options[options.size() - 7] = 0;
    raws.push_back(fixtures::ipv6(58, options, 255));
    auto check = [](const RawPacket &raw) {
        auto full = decodePacket(raw), summary = decodeSummary(raw);
        auto details = decodeDetails(raw);
        require(testing::sameSummary(full, summary), "Summary and full metadata identical");
        require(summary.fields.empty() && summary.fields.capacity() == 0,
                "Summary creates no field storage");
        require(full.fields == details.fields, "Borrowed details preserve all fields");
        std::size_t count = 0;
        require(testing::validFields(details.fields, raw.bytes.size(), count), "Details bounded");
        require(summary.raw.bytes == raw.bytes &&
                    summary.estimatedBytes == estimatePacketBytes(summary),
                "Summary owns exact raw data");
    };
    for (const auto &raw : raws) {
        check(raw);
        if (raw.bytes.size() < 1024)
            for (std::size_t n = 0; n < raw.bytes.size(); ++n) {
                auto cut = raw;
                cut.bytes.resize(n);
                check(cut);
            }
    }
    std::mt19937 rng(1600);
    for (int i = 0; i < 1000; ++i) {
        auto raw = raws[rng() % (raws.size() - 2)];
        raw.bytes[rng() % raw.bytes.size()] = static_cast<std::uint8_t>(rng());
        check(raw);
    }
    SessionStore full, summary;
    for (int i = 0; i < 10000; ++i) {
        const auto &raw = raws[static_cast<std::size_t>(i) % (raws.size() - 2)];
        full.append(decodePacket(raw));
        summary.append(decodeSummary(raw));
    }
    require(summary.packets().size() == 10000 &&
                summary.estimatedBytes() * 2 <= full.estimatedBytes(),
            "Summary cache saves at least half the full footprint");
}
void sessions() {
    SessionStore count(3, 100000);
    for (int i = 0; i < 10; ++i)
        count.append(decodePacket(fixtures::icmp()));
    require(count.packets().size() == 3 && count.stats().received == 10 &&
                count.stats().overwritten == 7,
            "Count ring eviction");
    require(count.packets().front()->id == 8 && count.packets().back()->id == 10,
            "Stable monotonic IDs");
    const auto size = fixtures::icmp().bytes.size();
    SessionStore bytes(100, size * 2);
    for (int i = 0; i < 5; ++i)
        bytes.append(decodePacket(fixtures::icmp()));
    require(bytes.rawBytes() == size * 2 && bytes.stats().overwritten == 3, "Byte cap eviction");
    SessionStore tiny(1, 1);
    tiny.append(decodePacket(fixtures::icmp()));
    require(tiny.packets().empty() && tiny.stats().overwritten == 1, "Single oversized packet");
    count.clear();
    require(count.stats().received == 0 && count.rawBytes() == 0 && count.packets().empty(),
            "Session clear");
}
} // namespace
int main() {
    try {
        addressFormatting();
        pcapWireEncoding();
        protocols();
        analysis();
        filters();
        ipv6();
        pcap();
        sessions();
        resourceBudgets();
        summaryModes();
        std::cout << "PASS: " << checks
                  << " checks (IPv4/IPv6 protocols, truncation/mutation, filtering, PCAP, cache)\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAIL after " << checks << " checks: " << e.what() << "\n";
        return 1;
    }
}
