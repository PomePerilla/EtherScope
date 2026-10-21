#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace etherscope {
struct Field {
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
    ChecksumStatus status{ChecksumStatus::NotChecked};
    std::optional<std::uint16_t> computed;
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
    ChecksumResult ipv4Checksum, icmpChecksum;
    std::vector<Field> fields;
    std::size_t estimatedBytes{};
};
inline constexpr std::size_t maxPacketFields=4096;
Packet decodePacket(RawPacket raw);
std::size_t estimatePacketBytes(const Packet& packet);
std::string formatMac(const std::array<std::uint8_t, 6>& address);
std::string formatIp(const std::array<std::uint8_t, 4>& address);
std::string formatIpv6(const std::array<std::uint8_t, 16>& address);
}
