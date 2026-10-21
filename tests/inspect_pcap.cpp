#include "core/pcap_file.h"
#include <iostream>
#include <string_view>

using namespace etherscope;
const Field* field(const std::vector<Field>& fields,std::string_view name) {
    for(const auto& f:fields)if(f.name==name)return &f;return nullptr;
}
std::string get(const Packet& packet,std::string_view group,std::string_view name) {
    if(group=="ICMPv6 NS" || group=="ICMPv6 NA") {
        const auto type=get(packet,"ICMPv6","类型");
        if(!type.starts_with(group=="ICMPv6 NS"?"135 ":"136 ")) return {};
        group="ICMPv6";
    }
    const auto* g=field(packet.fields,group);if(!g)return {};const auto* f=field(g->children,name);return f?f->value:"";
}
std::string option(const Packet& packet,std::string_view name,std::string_view kind={}) {
    const auto* ip=field(packet.fields,"IPv4");if(!ip)return {};
    const auto* options=field(ip->children,"选项与填充");if(!options)return {};
    for(const auto& item:options->children)if(kind.empty() || item.name==kind)if(const auto* value=field(item.children,name))return value->value;
    return {};
}
std::string checksumStatus(const Packet& packet,bool icmp) {
    if(!field(packet.fields,icmp?"ICMP":"IPv4"))return {};
    const auto& result=icmp?packet.icmpChecksum:packet.ipv4Checksum;
    return result.status==ChecksumStatus::Match?"1":(result.status==ChecksumStatus::Mismatch?"0":"2");
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
#else
int main(int argc,char** argv) {
#endif
    if(argc!=2) {std::cerr<<"usage: inspect_pcap capture.pcap\n";return 2;}
    try {
        PcapReader reader{std::filesystem::path(argv[1])};std::uint64_t count=0;
        std::cout<<"frame.number\tframe.len\tframe.cap_len\teth.src\teth.dst\teth.type\tvlan.id\tip.version\tip.hdr_len\tip.dscp\tip.ecn\tip.len\tip.id\tip.flags\tip.frag_offset\tip.ttl\tip.proto\tip.checksum\tip.src\tip.dst\ticmp.type\ticmp.code\ticmp.checksum\ticmp.ident\ticmp.seq\tarp.opcode\tarp.src.hw_mac\tarp.src.proto_ipv4\tarp.dst.hw_mac\tarp.dst.proto_ipv4\ttcp.srcport\ttcp.dstport\ttcp.seq_raw\ttcp.ack_raw\ttcp.hdr_len\ttcp.flags\ttcp.window\ttcp.checksum\ttcp.urgent\tudp.srcport\tudp.dstport\tudp.length\tudp.checksum"
                 <<"\tipv6.version\tipv6.tclass\tipv6.tclass.dscp\tipv6.tclass.ecn\tipv6.flow\tipv6.plen\tipv6.nxt\tipv6.hlim\tipv6.src\tipv6.dst\ticmpv6.type\ticmpv6.code\ticmpv6.checksum\ticmpv6.echo.identifier\ticmpv6.echo.sequence_number\ticmpv6.nd.ns.target_address\ticmpv6.nd.na.target_address\ticmpv6.mtu\tipv6.fraghdr.nxt\tipv6.fraghdr.offset\tipv6.fraghdr.more\tipv6.fraghdr.ident\tah.spi\tah.sequence"
                 <<"\tip.checksum.status\ticmp.checksum.status\tip.opt.type\tip.opt.len\tip.opt.ptr\tip.rec_rt\tip.opt.flag\tip.opt.overflow\tip.opt.time_stamp\tip.opt.time_stamp_addr\n";
        while(auto raw=reader.next()) {
            auto p=decodePacket(std::move(*raw));std::cout<<++count<<'\t'<<p.raw.originalLength<<'\t'<<p.raw.bytes.size();
            const std::pair<const char*,const char*> fields[]={
                {"Ethernet II","源 MAC"},{"Ethernet II","目的 MAC"},{"Ethernet II","类型/长度"},{"802.1Q","VLAN ID"},
                {"IPv4","版本"},{"IPv4","首部长度"},{"IPv4","区分服务 DSCP"},{"IPv4","ECN"},{"IPv4","总长度"},{"IPv4","标识"},{"IPv4","标志"},{"IPv4","片偏移"},{"IPv4","生存时间 TTL"},{"IPv4","上层协议"},{"IPv4","首部检验和"},{"IPv4","源地址"},{"IPv4","目的地址"},
                {"ICMP","类型"},{"ICMP","代码"},{"ICMP","检验和"},{"ICMP","标识符"},{"ICMP","序列号"},
                {"ARP","操作"},{"ARP","发送者 MAC"},{"ARP","发送者 IP"},{"ARP","目标 MAC"},{"ARP","目标 IP"},
                {"TCP","源端口"},{"TCP","目的端口"},{"TCP","序列号"},{"TCP","确认号"},{"TCP","首部长度"},{"TCP","标志"},{"TCP","窗口"},{"TCP","检验和"},{"TCP","紧急指针"},
                {"UDP","源端口"},{"UDP","目的端口"},{"UDP","长度"},{"UDP","检验和"},
                {"IPv6","版本"},{"IPv6","流量类别"},{"IPv6","区分服务 DSCP"},{"IPv6","ECN"},{"IPv6","流标签"},{"IPv6","有效载荷长度"},{"IPv6","下一首部"},{"IPv6","跳数限制"},{"IPv6","源地址"},{"IPv6","目的地址"},
                {"ICMPv6","类型"},{"ICMPv6","代码"},{"ICMPv6","检验和"},{"ICMPv6","标识符"},{"ICMPv6","序列号"},{"ICMPv6 NS","目标地址"},{"ICMPv6 NA","目标地址"},{"ICMPv6","MTU"},
                {"IPv6 Fragment","下一首部"},{"IPv6 Fragment","片偏移"},{"IPv6 Fragment","更多分片 M"},{"IPv6 Fragment","标识"},{"IPv6 AH","SPI"},{"IPv6 AH","序列号"}};
            for(const auto& [group,name]:fields)std::cout<<'\t'<<get(p,group,name);
            std::cout<<'\t'<<checksumStatus(p,false)<<'\t'<<checksumStatus(p,true)<<'\t'<<option(p,"类型")<<'\t'<<option(p,"长度")<<'\t'<<option(p,"指针")
                <<'\t'<<option(p,"地址 1","记录路由")<<'\t'<<option(p,"格式","时间戳")<<'\t'<<option(p,"溢出","时间戳")
                <<'\t'<<option(p,"时间戳 1","时间戳")<<'\t'<<option(p,"地址 1","时间戳")<<'\n';
        }return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
