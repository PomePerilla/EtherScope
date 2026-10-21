#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace etherscope {
struct Field {
    bool operator==(const Field&) const=default;
    std::string name;
    std::string value;
    std::size_t offset{};
    std::size_t length{};
    std::vector<Field> children;
};
struct RawPacket {
    std::int64_t timestampNs{};
    std::uint32_t linkType{1};
    std::uint32_t originalLength{};
    std::vector<std::uint8_t> bytes;
};
enum class ChecksumStatus { NotChecked, Match, Mismatch };
struct ChecksumResult {
    bool operator==(const ChecksumResult&) const=default;
    ChecksumStatus status{ChecksumStatus::NotChecked};
    std::optional<std::uint16_t> computed;
};
struct TcpInfo {
    bool operator==(const TcpInfo&) const=default;
    std::uint16_t sourcePort{},destinationPort{};
    std::uint32_t sequence{},acknowledgment{},payloadLength{};
    std::uint8_t flags{};
    bool completeSegment{};
    std::uint32_t payloadOffset{};
};
struct Packet {
    std::uint64_t id{};
    RawPacket raw;
    std::string protocol{"Ethernet"};
    std::string source, destination, summary, error;
    std::vector<std::string> warnings;
    std::optional<std::array<std::uint8_t, 6>> sourceMac, destinationMac;
    std::optional<std::array<std::uint8_t, 4>> sourceIp, destinationIp;
    std::optional<std::array<std::uint8_t, 16>> sourceIpv6, destinationIpv6;
    std::optional<std::uint8_t> icmpType;
    std::optional<TcpInfo> tcp;
    std::optional<std::uint16_t> vlanId;
    std::uint64_t tcpConversationId{};
    ChecksumResult ipv4Checksum, icmpChecksum;
    std::vector<Field> fields;
    std::size_t estimatedBytes{};
};
inline constexpr std::size_t maxPacketFields=4096;
struct PacketDetails {
    std::vector<Field> fields;
    std::size_t estimatedBytes{};
};
Packet decodePacket(RawPacket raw);
Packet decodeSummary(RawPacket raw);
PacketDetails decodeDetails(const RawPacket& raw);
std::size_t estimatePacketBytes(const Packet& packet);
std::string formatMac(const std::array<std::uint8_t, 6>& address);
std::string formatIp(const std::array<std::uint8_t, 4>& address);
std::string formatIpv6(const std::array<std::uint8_t, 16>& address);
}
