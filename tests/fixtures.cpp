#include "fixtures.h"
#include <algorithm>
#include <stdexcept>

namespace etherscope::fixtures {
RawPacket tcp(std::uint8_t flags,std::uint32_t sequence,std::uint32_t acknowledgment,bool reverse,std::uint16_t clientPort,bool v6,std::vector<std::uint8_t> payload) {
    std::vector<std::uint8_t> segment(20,0);
    auto put=[&](std::size_t offset,std::uint32_t value,int bytes){for(int i=0;i<bytes;++i)segment[offset+i]=static_cast<std::uint8_t>(value>>(8*(bytes-1-i)));};
    put(0,reverse?443:clientPort,2);put(2,reverse?clientPort:443,2);put(4,sequence,4);put(8,acknowledgment,4);segment[12]=0x50;segment[13]=flags;put(14,8192,2);
    segment.insert(segment.end(),payload.begin(),payload.end());
    auto raw=v6?ipv6(6,std::move(segment)):ipv4(6,std::move(segment));
    if(reverse) {
        auto& b=raw.bytes;const std::size_t first=v6?22:26,second=v6?38:30,count=v6?16:4;
        for(std::size_t i=0;i<count;++i)std::swap(b[first+i],b[second+i]);
        for(std::size_t i=0;i<6;++i)std::swap(b[i],b[i+6]);
    }
    return raw;
}
std::vector<RawPacket> tcpConversationSamples() {
    std::vector<RawPacket> result={tcp(2,100),tcp(2,100),tcp(18,500,101,true),tcp(16,101,501),tcp(24,101,501,false,50000,false,{'a','b','c'}),
        tcp(16,501,104,true),tcp(17,104,501),tcp(16,501,105,true),tcp(17,501,105,true),tcp(16,105,502),
        tcp(2,10,0,false,50000,true),tcp(20,0,11,true,50000,true),tcp(2,900),tcp(24,1000,2000,false,51000,false,{'x'}),tcp(16,2000,1001,true,51000)};
    for(std::size_t i=0;i<result.size();++i)result[i].timestampNs=1700000000000000000LL+static_cast<std::int64_t>(i)*10000000;
    return result;
}
namespace {
void put16(std::vector<std::uint8_t>& b,std::size_t o,std::uint16_t n) {b[o]=std::uint8_t(n>>8);b[o+1]=std::uint8_t(n);}
std::uint16_t checksum(const std::vector<std::uint8_t>& b,std::size_t start,std::size_t length) {
    std::uint32_t sum=0;for(std::size_t i=0;i<length;i+=2) sum+=(std::uint16_t(b[start+i])<<8)+(i+1<length?b[start+i+1]:0);
    while(sum>>16) sum=(sum&65535)+(sum>>16);return std::uint16_t(~sum);
}
RawPacket frame(std::uint16_t type,std::vector<std::uint8_t> payload) {
    RawPacket r;r.timestampNs=1700000000123456789LL;
    r.bytes={0x02,0,0,0,0,2,0x02,0,0,0,0,1,std::uint8_t(type>>8),std::uint8_t(type)};
    r.bytes.insert(r.bytes.end(),payload.begin(),payload.end());r.originalLength=static_cast<std::uint32_t>(r.bytes.size());return r;
}
}
RawPacket ipv4(std::uint8_t protocol,std::vector<std::uint8_t> payload,bool options,std::uint16_t fragment) {
    const std::size_t header=options?24:20;std::vector<std::uint8_t> b(header,0);
    b[0]=options?0x46:0x45;b[1]=0x2e;put16(b,2,static_cast<std::uint16_t>(header+payload.size()));put16(b,4,0x1234);put16(b,6,fragment);
    b[8]=64;b[9]=protocol;b[12]=192;b[13]=0;b[14]=2;b[15]=1;b[16]=192;b[17]=0;b[18]=2;b[19]=2;
    if(options) {b[20]=1;b[21]=1;}
    put16(b,10,checksum(b,0,header));b.insert(b.end(),payload.begin(),payload.end());return frame(0x0800,std::move(b));
}
RawPacket icmp(std::uint8_t type,std::uint8_t code) {
    std::vector<std::uint8_t> b{type,code,0,0,0x12,0x34,0,1};
    if(type==3 || type==11) {
        b[4]=b[5]=b[6]=b[7]=0;
        auto original=ipv4(17,{0x30,0x39,0x82,0x9a,0,8,0,0});
        b.insert(b.end(),original.bytes.begin()+14,original.bytes.end());
    } else b.insert(b.end(),{'E','t','h','e','r','S','c','o','p','e'});
    put16(b,2,checksum(b,0,b.size()));return ipv4(1,std::move(b));
}
RawPacket ipv4Options(std::vector<std::uint8_t> options) {
    if(options.size()>40)throw std::invalid_argument("IPv4 option fixture exceeds IHL");
    while(options.size()%4)options.push_back(0);
    auto packet=icmp();auto& bytes=packet.bytes;bytes.insert(bytes.begin()+34,options.begin(),options.end());
    bytes[14]=static_cast<std::uint8_t>(0x45+options.size()/4);put16(bytes,16,static_cast<std::uint16_t>(bytes.size()-14));
    bytes[24]=bytes[25]=0;put16(bytes,24,checksum(bytes,14,20+options.size()));packet.originalLength=static_cast<std::uint32_t>(bytes.size());return packet;
}
std::vector<RawPacket> analysisSamples() {
    std::vector<RawPacket> result={ipv4Options({1,1,0,0}),ipv4Options({7,7,8,192,0,2,254,0}),
        ipv4Options({68,8,9,0,0,0,0,42}),ipv4Options({68,12,13,1,192,0,2,254,0,0,0,42}),
        ipv4Options({68,12,5,3,192,0,2,254,0,0,0,0}),ipv4Options({0x9e,4,0xaa,0xbb})};
    auto badHeader=icmp();badHeader.bytes[24]^=1;result.push_back(std::move(badHeader));
    auto badIcmp=icmp();badIcmp.bytes.back()^=1;result.push_back(std::move(badIcmp));
    result.push_back(ipv4(1,{8,0,0xf6,0xff,0,0,0,0,1}));
    result.push_back(ipv4(1,{0,0,0,0,0,0,0,0,0xff,0xff}));
    result.push_back(ipv4(6,{0x30,0x39,0,80,0,0,0,1},false,0x2000));
    std::vector<std::uint8_t> tcp(24,0);tcp[12]=0xa0;result.push_back(ipv4(6,tcp,false,0x2000));
    auto shortIcmp=icmp();shortIcmp.bytes.pop_back();result.push_back(std::move(shortIcmp));
    result.push_back(ipv4(1,{8,0,0xf7,0xff,0,0,0,0},false,0x2000));
    result.push_back(ipv4Options({0x9e,5,0xaa,0xbb}));result.push_back(ipv4Options({7,7,5,192,0,2,254,0}));
    result.push_back(ipv4Options({68,7,5,1,0,0,0,0}));result.push_back(ipv4Options({68,4,5,2}));
    return result;
}
RawPacket ipv6(std::uint8_t next,std::vector<std::uint8_t> payload,std::uint8_t hopLimit) {
    std::vector<std::uint8_t> b(40,0);b[0]=0x62;b[1]=0xe1;b[2]=0x23;b[3]=0x45;
    put16(b,4,static_cast<std::uint16_t>(payload.size()));b[6]=next;b[7]=hopLimit;
    for(auto offset:{8u,24u}) {b[offset]=0x20;b[offset+1]=1;b[offset+2]=0x0d;b[offset+3]=0xb8;}
    b[23]=1;b[39]=2;
    const std::size_t checkOffset=next==58?2:(next==17?6:16);
    if((next==58 || next==17 || next==6) && payload.size()>=checkOffset+2) {
        payload[checkOffset]=payload[checkOffset+1]=0;
        std::vector<std::uint8_t> pseudo(b.begin()+8,b.end());pseudo.insert(pseudo.end(),{0,0,std::uint8_t(payload.size()>>8),std::uint8_t(payload.size()),0,0,0,next});
        pseudo.insert(pseudo.end(),payload.begin(),payload.end());auto sum=checksum(pseudo,0,pseudo.size());
        put16(payload,checkOffset,sum==0 && next==17?65535:sum);
    }
    b.insert(b.end(),payload.begin(),payload.end());return frame(0x86dd,std::move(b));
}
std::vector<RawPacket> ipv6Samples() {
    std::vector<RawPacket> result;
    for(auto type:{128,129}) result.push_back(ipv6(58,{std::uint8_t(type),0,0,0,0x12,0x34,0,1,'I','P','v','6'}));
    std::vector<std::uint8_t> tcp(20,0);put16(tcp,0,12345);put16(tcp,2,443);tcp[7]=42;tcp[12]=0x50;tcp[13]=2;put16(tcp,14,4096);
    result.push_back(ipv6(6,tcp));result.push_back(ipv6(17,{0x30,0x39,0,53,0,12,0,0,'v','6','o','k'}));
    auto extend=[](RawPacket packet,std::uint8_t next,std::vector<std::uint8_t> headers) {
        packet.bytes[20]=next;packet.bytes.insert(packet.bytes.begin()+54,headers.begin(),headers.end());
        put16(packet.bytes,18,static_cast<std::uint16_t>(packet.bytes.size()-54));packet.originalLength=static_cast<std::uint32_t>(packet.bytes.size());return packet;
    };
    result.push_back(extend(result[3],0,{43,0,1,4,0,0,0,0,60,0,253,0,0,0,0,0,17,0,1,4,0,0,0,0}));
    auto firstFragment=extend(result[3],44,{17,0,0,1,0x12,0x34,0x56,0x78});
    firstFragment.bytes.resize(firstFragment.bytes.size()-4);firstFragment.originalLength-=4;put16(firstFragment.bytes,18,16);result.push_back(firstFragment);
    result.push_back(ipv6(44,{6,0,0,8,0x12,0x34,0x56,0x78,0,0,0,0,0,0,0,0}));
    result.push_back(extend(result[3],44,{17,0,0,0,0x12,0x34,0x56,0x78})); // atomic fragment
    result.push_back(extend(result[2],51,{6,4,0,0,0,0,0,7,0,0,0,9,1,2,3,4,5,6,7,8,9,10,11,12}));
    result.push_back(ipv6(50,{0,0,0,7,0,0,0,9,1,2,3,4,5,6,7,8}));result.push_back(ipv6(59,{}));
    std::vector<std::uint8_t> nd(24,0);nd[0]=135;nd[8]=0x20;nd[9]=1;nd[10]=0x0d;nd[11]=0xb8;nd[23]=2;nd.insert(nd.end(),{1,1,2,0,0,0,0,1});
    result.push_back(ipv6(58,nd,255));nd[0]=136;nd[4]=0x60;nd[24]=2;result.push_back(ipv6(58,nd,255));
    result.push_back(ipv6(58,{133,0,0,0,0,0,0,0,1,1,2,0,0,0,0,1},255));
    std::vector<std::uint8_t> ra{134,0,0,0,64,0xc0,0x07,0x08,0,0,0x75,0x30,0,0,3,0xe8};
    ra.insert(ra.end(),{5,1,0,0,0,0,0x05,0xdc});
    std::vector<std::uint8_t> prefix(32,0);prefix[0]=3;prefix[1]=4;prefix[2]=64;prefix[3]=0xc0;prefix[6]=0x0e;prefix[7]=0x10;prefix[10]=0x07;prefix[11]=0x08;
    prefix[16]=0x20;prefix[17]=1;prefix[18]=0x0d;prefix[19]=0xb8;ra.insert(ra.end(),prefix.begin(),prefix.end());result.push_back(ipv6(58,ra,255));
    std::vector<std::uint8_t> redirect(40,0);redirect[0]=137;redirect[8]=redirect[24]=0x20;redirect[9]=redirect[25]=1;redirect[10]=redirect[26]=0x0d;redirect[11]=redirect[27]=0xb8;redirect[23]=2;redirect[39]=3;result.push_back(ipv6(58,redirect,255));
    for(auto type:{1,2,3,4}) {std::vector<std::uint8_t> error{std::uint8_t(type),0,0,0,0,0,0x05,0xdc};error.insert(error.end(),result[3].bytes.begin()+14,result[3].bytes.end());result.push_back(ipv6(58,error));}
    auto vlan=result[0];vlan.bytes.insert(vlan.bytes.begin()+12,{0x81,0,0,42});vlan.originalLength+=4;result.push_back(vlan);
    for(std::size_t i=0;i<result.size();++i) result[i].timestampNs+=static_cast<std::int64_t>(i)*100000000;
    return result;
}
std::vector<RawPacket> samples() {
    std::vector<RawPacket> result{icmp(8),icmp(0),icmp(11,0),icmp(3,3)};
    std::vector<std::uint8_t> arp{0,1,8,0,6,4,0,1,2,0,0,0,0,1,192,0,2,1,0,0,0,0,0,0,192,0,2,2};
    result.push_back(frame(0x0806,std::move(arp)));
    std::vector<std::uint8_t> tcp(24,0);put16(tcp,0,12345);put16(tcp,2,443);tcp[7]=42;tcp[12]=0x60;tcp[13]=2;put16(tcp,14,64240);tcp[20]=2;tcp[21]=4;put16(tcp,22,1460);
    result.push_back(ipv4(6,std::move(tcp)));
    result.push_back(ipv4(17,{0x30,0x39,0,53,0,12,0,0,'t','e','s','t'}));
    auto options=icmp();std::vector<std::uint8_t> payload(options.bytes.begin()+34,options.bytes.end());result.push_back(ipv4(1,std::move(payload),true));
    auto vlan=icmp();vlan.bytes.insert(vlan.bytes.begin()+12,{0x81,0,0,42});vlan.originalLength+=4;result.push_back(vlan);
    result.push_back(ipv4(1,{0xde,0xad,0xbe,0xef,0,0,0,0},false,0x0010));
    result.push_back(frame(0x88b5,{1,2,3,4}));
    auto truncated=icmp();truncated.bytes.resize(38);result.push_back(truncated);
    for(std::size_t i=0;i<result.size();++i) result[i].timestampNs+=static_cast<std::int64_t>(i)*100000000;
    return result;
}
}
