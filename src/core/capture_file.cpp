#include "core/capture_file.h"
#include "core/bytes.h"
#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <stdexcept>

namespace etherscope {
namespace {
constexpr std::uint32_t shb=0x0a0d0d0a;
void read(std::istream& stream,std::span<std::uint8_t> bytes) {
    if(bytes.empty())return;
    stream.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    if(static_cast<std::size_t>(stream.gcount())!=bytes.size())throw std::runtime_error("Capture file is truncated");
}
void put(std::vector<std::uint8_t>& out,std::uint64_t value,unsigned width) {
    for(unsigned i=0;i<width;++i)out.push_back(static_cast<std::uint8_t>(value>>(i*8)));
}
void pad(std::vector<std::uint8_t>& out) {while(out.size()%4)out.push_back(0);}
void option(std::vector<std::uint8_t>& out,std::uint16_t code,std::span<const std::uint8_t> value) {
    if(value.size()>65535)throw std::runtime_error("Capture option is too long");
    put(out,code,2);put(out,value.size(),2);out.insert(out.end(),value.begin(),value.end());pad(out);
}
template<class F> void options(std::span<const std::uint8_t> bytes,bool little,F accept) {
    ByteView b(bytes);std::size_t cursor=0;
    while(cursor<bytes.size()) {
        const auto code=b.integer(cursor,2,little),length=b.integer(cursor+2,2,little);cursor+=4;
        const auto value=b.slice(cursor,static_cast<std::size_t>(length));
        if(!code){if(length)throw std::runtime_error("Invalid capture option terminator");return;}
        accept(code,value);const auto padded=(length+3)&~std::uint64_t(3);
        b.slice(cursor,static_cast<std::size_t>(padded));cursor+=static_cast<std::size_t>(padded);
    }
}
std::int64_t timestamp(std::uint64_t ticks,std::uint8_t resolution,std::int64_t offset) {
    std::uint64_t denominator=1;const auto exponent=resolution&127;
    if(resolution&128){if(exponent>63)throw std::runtime_error("Invalid timestamp resolution");denominator=std::uint64_t(1)<<exponent;}
    else {if(exponent>19)throw std::runtime_error("Invalid timestamp resolution");for(int i=0;i<exponent;++i)denominator*=10;}
    const auto seconds=ticks/denominator;auto remainder=ticks%denominator;
    if(seconds>std::uint64_t(INT64_MAX/1000000000))throw std::runtime_error("Capture timestamp is out of range");
    // Decimal long division avoids 128-bit arithmetic and multiplication overflow.
    std::uint64_t fraction=0;
    for(unsigned i=0;i<9;++i) {
        unsigned digit=0;std::uint64_t next=0;
        for(unsigned j=0;j<10;++j){if(next>=denominator-remainder){next-=denominator-remainder;++digit;}else next+=remainder;}
        fraction=fraction*10+digit;remainder=next;
    }
    const auto total=seconds*1000000000+fraction;if(total>std::uint64_t(INT64_MAX))throw std::runtime_error("Capture timestamp is out of range");
    auto result=static_cast<std::int64_t>(total);
    if(offset>INT64_MAX/1000000000 || offset<INT64_MIN/1000000000)throw std::runtime_error("Capture timestamp offset is out of range");
    offset*=1000000000;
    if((offset>0 && result>INT64_MAX-offset) || (offset<0 && result<INT64_MIN-offset))throw std::runtime_error("Capture timestamp is out of range");
    return result+offset;
}
void validate(const RawPacket& p) {
    if(p.bytes.size()>maxCaptureRecord || p.originalLength<p.bytes.size())throw std::runtime_error("Invalid capture record length");
}
}
CaptureReader::CaptureReader(const std::filesystem::path& path):stream_(path,std::ios::binary) {
    if(!stream_)throw std::runtime_error("无法打开 PCAP 文件");
    std::array<std::uint8_t,12> first{};read(stream_,first);ByteView b(first);
    if(b.integer(0,4,true)==shb) {
        format_=CaptureFormat::Pcapng;const auto magic=b.integer(8,4,true);
        if(magic!=0x1a2b3c4d && magic!=0x4d3c2b1a)throw std::runtime_error("Invalid PCAPNG byte order");
        little_=magic==0x1a2b3c4d;const auto length=b.integer(4,4,little_);
        if(length<28 || length%4 || length>maxCaptureRecord)throw std::runtime_error("Invalid PCAPNG section length");
        std::vector<std::uint8_t> body(static_cast<std::size_t>(length)-12);read(stream_,body);
        if(ByteView(body).integer(body.size()-4,4,little_)!=length)throw std::runtime_error("PCAPNG block lengths differ");
        std::vector<std::uint8_t> sectionBody(first.begin()+8,first.end());sectionBody.insert(sectionBody.end(),body.begin(),body.end()-4);section(sectionBody);return;
    }
    const auto magic=b.integer(0,4,true);
    if(magic==0xa1b2c3d4 || magic==0xa1b23c4d){little_=true;nano_=magic==0xa1b23c4d;}
    else if(magic==0xd4c3b2a1 || magic==0x4d3cb2a1){little_=false;nano_=magic==0x4d3cb2a1;}
    else throw std::runtime_error("Unsupported capture file format");
    std::array<std::uint8_t,12> rest{};read(stream_,rest);ByteView r(rest);
    if(b.integer(4,2,little_)!=2 || b.integer(6,2,little_)!=4)throw std::runtime_error("不支持的 PCAP 版本");
    snapLength_=static_cast<std::uint32_t>(r.integer(4,4,little_));const auto linkInfo=r.integer(8,4,little_);linkType_=static_cast<std::uint32_t>(linkInfo&65535);
    if(!snapLength_ || snapLength_>maxCaptureRecord)throw std::runtime_error("PCAP 快照长度异常");
    if(linkInfo&0xfc000000u)throw std::runtime_error("暂不支持声明了 FCS 元信息的 PCAP，请先转换");
    if(linkType_!=1)throw std::runtime_error("该 PCAP 不是 Ethernet 链路，不能作为以太网帧解析");
}
void CaptureReader::section(std::span<const std::uint8_t> body) {
    ByteView b(body);if(body.size()<16 || b.integer(4,2,little_)!=1 || b.integer(6,2,little_)!=0)throw std::runtime_error("Unsupported PCAPNG section version");
    interfaces_.clear();options(body.subspan(16),little_,[](auto,auto){});
}
std::optional<RawPacket> CaptureReader::next() {return format_==CaptureFormat::Pcap?nextPcap():nextPcapng();}
std::optional<RawPacket> CaptureReader::nextPcap() {
    std::array<std::uint8_t,16> h{};stream_.read(reinterpret_cast<char*>(h.data()),h.size());
    if(stream_.gcount()==0 && stream_.eof())return {};
    if(stream_.gcount()!=16)throw std::runtime_error("PCAP 数据包记录头被截断");
    ByteView b(h);const auto seconds=b.integer(0,4,little_),fraction=b.integer(4,4,little_),cap=b.integer(8,4,little_),original=b.integer(12,4,little_);
    if(cap>snapLength_ || cap>maxCaptureRecord || original<cap || fraction>=(nano_?1000000000u:1000000u))throw std::runtime_error("PCAP 数据包长度或时间戳异常");
    RawPacket raw;raw.linkType=linkType_;raw.originalLength=static_cast<std::uint32_t>(original);raw.timestampNs=static_cast<std::int64_t>(seconds*1000000000+(nano_?fraction:fraction*1000));
    raw.bytes.resize(static_cast<std::size_t>(cap));read(stream_,raw.bytes);return raw;
}
std::optional<RawPacket> CaptureReader::nextPcapng() {
    for(;;) {
        std::array<std::uint8_t,8> h{};stream_.read(reinterpret_cast<char*>(h.data()),h.size());
        if(stream_.gcount()==0 && stream_.eof())return {};
        if(stream_.gcount()!=8)throw std::runtime_error("Capture file is truncated");
        ByteView header(h);const auto type=static_cast<std::uint32_t>(header.integer(0,4,little_));std::vector<std::uint8_t> prefix;
        if(type==shb) {
            prefix.resize(4);read(stream_,prefix);const auto magic=ByteView(prefix).integer(0,4,true);
            if(magic!=0x1a2b3c4d && magic!=0x4d3c2b1a)throw std::runtime_error("Invalid PCAPNG byte order");little_=magic==0x1a2b3c4d;
        }
        const auto length=header.integer(4,4,little_);
        if(length<12+prefix.size() || length%4)throw std::runtime_error("Invalid PCAPNG block length");
        const bool known=type==shb || type==1 || type==2 || type==3 || type==6;
        if(known && length>maxCaptureRecord+65536u)throw std::runtime_error("PCAPNG block exceeds limit");
        std::vector<std::uint8_t> body;
        if(known) {body=std::move(prefix);const auto previous=body.size();body.resize(static_cast<std::size_t>(length)-12);read(stream_,std::span(body).subspan(previous));}
        else {stream_.seekg(static_cast<std::streamoff>(length)-12,std::ios::cur);if(!stream_)throw std::runtime_error("Capture file is truncated");}
        std::array<std::uint8_t,4> tail{};read(stream_,tail);if(ByteView(tail).integer(0,4,little_)!=length)throw std::runtime_error("PCAPNG block lengths differ");
        if(!known)continue;ByteView b(body);
        if(type==shb){section(body);continue;}
        if(type==1) {
            if(interfaces_.size()>=1024 || nextInterface_==UINT32_MAX)throw std::runtime_error("Capture interface limit reached");
            Interface i;i.id=nextInterface_++;i.link=static_cast<std::uint32_t>(b.integer(0,2,little_));i.snap=static_cast<std::uint32_t>(b.integer(4,4,little_));i.info=std::make_shared<CaptureInterfaceInfo>();i.info->snapLength=i.snap;
            if(i.snap>maxCaptureRecord)throw std::runtime_error("Invalid interface snapshot length");
            options(b.slice(8,body.size()-8),little_,[&](auto code,auto value){
                if(code==2 || code==3) {
                    metadataBytes_+=value.size();if(metadataBytes_>4*1024*1024)throw std::runtime_error("Capture metadata limit reached");
                    auto& text=code==2?i.info->name:i.info->description;text.assign(reinterpret_cast<const char*>(value.data()),value.size());
                } else if(code==9){if(value.size()!=1)throw std::runtime_error("Invalid timestamp resolution");i.resolution=value[0];timestamp(0,i.resolution,0);}
                else if(code==14){if(value.size()!=8)throw std::runtime_error("Invalid timestamp offset");i.offset=std::bit_cast<std::int64_t>(ByteView(value).integer(0,8,little_));}
                else if(code==13){if(value.size()!=1)throw std::runtime_error("Invalid FCS length");i.info->fcsLength=value[0];}
            });
            if(interfaces_.empty())linkType_=i.link;interfaces_.push_back(std::move(i));continue;
        }
        const bool simple=type==3;const auto index=simple?0:b.integer(0,type==2?2:4,little_);
        if(index>=interfaces_.size())throw std::runtime_error("Invalid PCAPNG interface reference");const auto& i=interfaces_[static_cast<std::size_t>(index)];
        RawPacket raw;raw.linkType=i.link;raw.interfaceId=i.id;raw.interfaceInfo=i.info;raw.timestampValid=!simple;
        raw.originalLength=static_cast<std::uint32_t>(b.integer(simple?0:16,4,little_));
        const auto cap=simple?std::min(raw.originalLength,i.snap?i.snap:raw.originalLength):static_cast<std::uint32_t>(b.integer(12,4,little_));
        if(cap>maxCaptureRecord || cap>raw.originalLength || (i.snap && cap>i.snap))throw std::runtime_error("Invalid capture record length");
        const std::size_t start=simple?4:20;const auto bytes=b.slice(start,cap);const auto end=start+((std::size_t(cap)+3)&~std::size_t(3));b.slice(start,end-start);
        if(simple){if(end!=body.size())throw std::runtime_error("Invalid simple packet length");}
        else {raw.timestampNs=timestamp((b.integer(4,4,little_)<<32)|b.integer(8,4,little_),i.resolution,i.offset);options(b.slice(end,body.size()-end),little_,[](auto,auto){});}
        raw.bytes.assign(bytes.begin(),bytes.end());return raw;
    }
}
void CaptureWriter::output(std::span<const std::uint8_t> bytes) {
    stream_.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    if(!stream_)throw std::runtime_error("PCAP 文件写入失败");bytes_+=bytes.size();
}
void CaptureWriter::block(std::uint32_t type,std::span<const std::uint8_t> body) {
    std::vector<std::uint8_t> h;put(h,type,4);put(h,body.size()+12,4);output(h);output(body);h.clear();put(h,body.size()+12,4);output(h);
}
CaptureWriter::CaptureWriter(std::ostream& stream,CaptureFormat format,std::span<const RawPacket* const> packets):stream_(stream),format_(format) {
    std::map<std::uint32_t,const RawPacket*> examples;
    for(const auto* p:packets) {
        if(!p)throw std::runtime_error("Invalid capture packet");validate(*p);
        auto [it,inserted]=interfaces_.try_emplace(p->interfaceId,Interface{0,p->linkType,65535});
        if(it->second.link!=p->linkType)throw std::runtime_error("Capture interface link types differ");
        it->second.snap=std::max(it->second.snap,static_cast<std::uint32_t>(p->bytes.size()));if(inserted)examples[p->interfaceId]=p;
    }
    if(interfaces_.empty())interfaces_.emplace(0,Interface{0,1,65535});
    if(format==CaptureFormat::Pcap) {
        if(interfaces_.size()!=1 || interfaces_.begin()->second.link!=1)throw std::runtime_error("PCAP requires one Ethernet interface");
        for(const auto* p:packets)if(!p->timestampValid || p->timestampNs<0 || p->timestampNs/1000000000>UINT32_MAX)throw std::runtime_error("PCAP timestamp is out of range");
        std::vector<std::uint8_t> h;put(h,0xa1b23c4d,4);put(h,0x00040002,4);put(h,0,8);put(h,interfaces_.begin()->second.snap,4);put(h,1,4);output(h);return;
    }
    for(const auto* p:packets) {
        if(p->timestampValid && p->timestampNs<0)throw std::runtime_error("PCAPNG timestamp is out of range");
        if(!p->timestampValid && (interfaces_.size()!=1 || p->bytes.size()!=std::min<std::size_t>(p->originalLength,interfaces_.begin()->second.snap)))throw std::runtime_error("Missing timestamp cannot be represented losslessly");
    }
    std::vector<std::uint8_t> body;put(body,0x1a2b3c4d,4);put(body,1,2);put(body,0,2);put(body,UINT64_MAX,8);block(shb,body);
    std::uint32_t index=0;
    for(auto& [id,i]:interfaces_) {
        i.index=index++;body.clear();if(i.link>65535)throw std::runtime_error("Invalid link type");put(body,i.link,2);put(body,0,2);put(body,i.snap,4);
        const std::uint8_t resolution=9;option(body,9,std::span(&resolution,1));
        if(examples.contains(id) && examples[id]->interfaceInfo) {
            const auto& info=*examples[id]->interfaceInfo;
            for(const auto pair:{std::pair{2,&info.name},std::pair{3,&info.description}})if(!pair.second->empty())option(body,static_cast<std::uint16_t>(pair.first),{reinterpret_cast<const std::uint8_t*>(pair.second->data()),pair.second->size()});
            if(info.fcsLength)option(body,13,std::span(&*info.fcsLength,1));
        }
        put(body,0,4);block(1,body);
    }
}
void CaptureWriter::write(const RawPacket& p) {
    validate(p);const auto it=interfaces_.find(p.interfaceId);
    if(it==interfaces_.end() || it->second.link!=p.linkType || p.bytes.size()>it->second.snap)throw std::runtime_error("Invalid capture interface");
    std::vector<std::uint8_t> body;
    if(format_==CaptureFormat::Pcap) {
        if(!p.timestampValid || p.timestampNs<0 || p.timestampNs/1000000000>UINT32_MAX)throw std::runtime_error("PCAP timestamp is out of range");
        put(body,static_cast<std::uint64_t>(p.timestampNs/1000000000),4);put(body,static_cast<std::uint64_t>(p.timestampNs%1000000000),4);put(body,p.bytes.size(),4);put(body,p.originalLength,4);output(body);output(p.bytes);return;
    }
    if(!p.timestampValid) {
        if(interfaces_.size()!=1 || p.bytes.size()!=std::min<std::size_t>(p.originalLength,it->second.snap))throw std::runtime_error("Missing timestamp cannot be represented losslessly");
        put(body,p.originalLength,4);body.insert(body.end(),p.bytes.begin(),p.bytes.end());pad(body);block(3,body);return;
    }
    if(p.timestampNs<0)throw std::runtime_error("PCAPNG timestamp is out of range");
    put(body,it->second.index,4);put(body,static_cast<std::uint64_t>(p.timestampNs)>>32,4);put(body,static_cast<std::uint64_t>(p.timestampNs)&UINT32_MAX,4);put(body,p.bytes.size(),4);put(body,p.originalLength,4);
    body.insert(body.end(),p.bytes.begin(),p.bytes.end());pad(body);block(6,body);
}
void writeCapture(std::ostream& stream,std::span<const Packet* const> packets,CaptureFormat format) {
    std::vector<const RawPacket*> raw;raw.reserve(packets.size());for(const auto* p:packets){if(!p)throw std::runtime_error("Invalid capture packet");raw.push_back(&p->raw);}
    CaptureWriter writer(stream,format,raw);for(const auto* p:raw)writer.write(*p);
}
}
