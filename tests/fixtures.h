#pragma once
#include "core/packet.h"
namespace etherscope::fixtures {
RawPacket icmp(std::uint8_t type=8,std::uint8_t code=0);
RawPacket ipv4(std::uint8_t protocol,std::vector<std::uint8_t> payload,bool options=false,std::uint16_t fragment=0);
std::vector<RawPacket> samples();
RawPacket ipv6(std::uint8_t next,std::vector<std::uint8_t> payload,std::uint8_t hopLimit=64);
std::vector<RawPacket> ipv6Samples();
RawPacket ipv4Options(std::vector<std::uint8_t> options);
std::vector<RawPacket> analysisSamples();
RawPacket tcp(std::uint8_t flags,std::uint32_t sequence,std::uint32_t acknowledgment=0,bool reverse=false,
    std::uint16_t clientPort=50000,bool v6=false,std::vector<std::uint8_t> payload={});
std::vector<RawPacket> tcpConversationSamples();
}
