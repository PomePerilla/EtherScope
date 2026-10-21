#include "core/pcap_file.h"
#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace etherscope {
namespace {
constexpr std::uint32_t maxFrame=16*1024*1024;
void put32(char* out,std::uint32_t value) {
    for(unsigned i=0;i<4;++i)out[i]=static_cast<char>(value>>(i*8));
}
}
std::uint32_t PcapReader::number(const std::uint8_t* p) const {
    if(little_) return std::uint32_t(p[0]) | (std::uint32_t(p[1])<<8) | (std::uint32_t(p[2])<<16) | (std::uint32_t(p[3])<<24);
    return std::uint32_t(p[3]) | (std::uint32_t(p[2])<<8) | (std::uint32_t(p[1])<<16) | (std::uint32_t(p[0])<<24);
}
PcapReader::PcapReader(const std::filesystem::path& path):stream_(path,std::ios::binary) {
    if(!stream_) throw std::runtime_error("无法打开 PCAP 文件");
    std::array<std::uint8_t,24> h{}; stream_.read(reinterpret_cast<char*>(h.data()),h.size());
    if(stream_.gcount()!=24) throw std::runtime_error("PCAP 文件头被截断");
    const std::array<std::uint8_t,4> magic{h[0],h[1],h[2],h[3]};
    if(magic==std::array<std::uint8_t,4>{0xd4,0xc3,0xb2,0xa1}) { little_=true; nano_=false; }
    else if(magic==std::array<std::uint8_t,4>{0xa1,0xb2,0xc3,0xd4}) { little_=false; nano_=false; }
    else if(magic==std::array<std::uint8_t,4>{0x4d,0x3c,0xb2,0xa1}) { little_=true; nano_=true; }
    else if(magic==std::array<std::uint8_t,4>{0xa1,0xb2,0x3c,0x4d}) { little_=false; nano_=true; }
    else throw std::runtime_error("仅支持经典 PCAP；PCAPNG 请先用 Wireshark 另存为 PCAP");
    const auto version=little_?(h[4]|(h[5]<<8)):(h[5]|(h[4]<<8));
    const auto minor=little_?(h[6]|(h[7]<<8)):(h[7]|(h[6]<<8));
    if(version!=2 || minor!=4) throw std::runtime_error("不支持的 PCAP 版本");
    snapLength_=number(h.data()+16); const auto linkInfo=number(h.data()+20); linkType_=linkInfo&0xffff;
    if(snapLength_==0 || snapLength_>maxFrame) throw std::runtime_error("PCAP 快照长度异常");
    if((linkInfo & 0xfc000000u)!=0) throw std::runtime_error("暂不支持声明了 FCS 元信息的 PCAP，请先转换");
    if(linkType_!=1) throw std::runtime_error("该 PCAP 不是 Ethernet 链路，不能作为以太网帧解析");
}
std::optional<RawPacket> PcapReader::next() {
    std::array<std::uint8_t,16> h{}; stream_.read(reinterpret_cast<char*>(h.data()),h.size());
    if(stream_.gcount()==0 && stream_.eof()) return {};
    if(stream_.gcount()!=16) throw std::runtime_error("PCAP 数据包记录头被截断");
    auto seconds=number(h.data()),fraction=number(h.data()+4),cap=number(h.data()+8),original=number(h.data()+12);
    if(cap>snapLength_ || cap>maxFrame || original<cap || fraction>=(nano_?1000000000u:1000000u))
        throw std::runtime_error("PCAP 数据包长度或时间戳异常");
    RawPacket raw; raw.linkType=linkType_; raw.originalLength=original;
    raw.timestampNs=std::int64_t(seconds)*1000000000+(nano_?fraction:std::int64_t(fraction)*1000);
    raw.bytes.resize(cap); stream_.read(reinterpret_cast<char*>(raw.bytes.data()),cap);
    if(static_cast<std::uint32_t>(stream_.gcount())!=cap) throw std::runtime_error("PCAP 数据包内容被截断");
    return raw;
}
void writePcap(std::ostream& s,std::span<const Packet* const> packets) {
    std::uint32_t snap=65535;
    for(const auto* p:packets) {
        if(!p || p->raw.linkType!=1 || p->raw.originalLength<p->raw.bytes.size() || p->raw.bytes.size()>maxFrame || p->raw.timestampNs<0
           || p->raw.timestampNs/1000000000>std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("待保存数据包的链路、长度或时间戳无效");
        snap=std::max(snap,static_cast<std::uint32_t>(p->raw.bytes.size()));
    }
    std::array<char,24> header{};
    put32(header.data(),0xa1b23c4d);put32(header.data()+4,0x00040002);
    put32(header.data()+16,snap);put32(header.data()+20,1);
    s.write(header.data(),header.size());
    for(const auto* p:packets) {
        std::array<char,16> record{};
        put32(record.data(),static_cast<std::uint32_t>(p->raw.timestampNs/1000000000));
        put32(record.data()+4,static_cast<std::uint32_t>(p->raw.timestampNs%1000000000));
        put32(record.data()+8,static_cast<std::uint32_t>(p->raw.bytes.size()));
        put32(record.data()+12,p->raw.originalLength);
        s.write(record.data(),record.size());
        s.write(reinterpret_cast<const char*>(p->raw.bytes.data()),static_cast<std::streamsize>(p->raw.bytes.size()));
    }
    if(!s) throw std::runtime_error("PCAP 文件写入失败");
}
}
