#include "core/packet.h"
#include <algorithm>
#include <charconv>
#include <span>

namespace etherscope {
namespace {
std::string hex(std::uint64_t value, int width = 2) {
    std::array<char,16> digits{};
    const auto end=std::to_chars(digits.data(),digits.data()+digits.size(),value,16).ptr;
    for(auto* digit=digits.data();digit!=end;++digit) {
        if(*digit>='a' && *digit<='f')*digit=static_cast<char>(*digit-'a'+'A');
    }
    const auto length=static_cast<std::size_t>(end-digits.data());
    std::string result("0x");
    if(width>0 && static_cast<std::size_t>(width)>length)result.append(static_cast<std::size_t>(width)-length,'0');
    result.append(digits.data(),length);
    return result;
}
struct Decoder {
    Packet p;
    std::span<const std::uint8_t> b;
    explicit Decoder(RawPacket raw) { p.raw = std::move(raw); b = p.raw.bytes; }
    bool has(std::size_t offset, std::size_t n, std::size_t end) const {
        return offset <= end && n <= end - offset && end <= b.size();
    }
    std::uint16_t u16(std::size_t o) const { return std::uint16_t((b[o] << 8) | b[o+1]); }
    std::uint32_t u32(std::size_t o) const { return (std::uint32_t(b[o]) << 24) | (std::uint32_t(b[o+1]) << 16) | (std::uint32_t(b[o+2]) << 8) | b[o+3]; }
    template<std::size_t N> std::array<std::uint8_t, N> address(std::size_t o) const {
        std::array<std::uint8_t,N> a{}; std::copy_n(b.begin()+o,N,a.begin()); return a;
    }
    void fail(const std::string& message) { if (p.error.empty()) p.error = message; }
    std::size_t fieldCount_{};
    bool fieldsLimited_{};
    void append(std::vector<Field>& target,Field field) {
        if(fieldCount_>=maxPacketFields) {
            if(!fieldsLimited_){fieldsLimited_=true;p.warnings.push_back("字段上限");}
            if(field.children.empty())return;
            auto nodes=[](auto&& self,const Field& value)->std::size_t {std::size_t count=1;for(const auto& child:value.children)count+=self(self,child);return count;};
            fieldCount_-=nodes(nodes,field.children.back());field.children.pop_back();
        }
        ++fieldCount_;target.push_back(std::move(field));
    }
    void add(Field& group, const std::string& name, const std::string& value, std::size_t o, std::size_t n) {
        append(group.children,{name,value,o,n,{}});
    }
    ChecksumResult checksum(std::size_t o,std::size_t end,std::size_t check) const {
        std::uint32_t sum=0;
        for(auto cursor=o;cursor<end;cursor+=2) {
            if(cursor==check)continue;
            sum+=(std::uint32_t(b[cursor])<<8)|(cursor+1<end?b[cursor+1]:0);
        }
        auto fold=[](std::uint32_t value){while(value>>16)value=(value&65535)+(value>>16);return value;};
        sum=fold(sum);
        return {fold(sum+u16(check))==65535?ChecksumStatus::Match:ChecksumStatus::Mismatch,static_cast<std::uint16_t>(~sum)};
    }
    void checksumField(Field& group,const std::string& name,std::size_t o,const ChecksumResult& result) {
        Field field{name,hex(u16(o),4),o,2,{}};
        add(field,"校验状态",result.status==ChecksumStatus::Match?"一致":(result.status==ChecksumStatus::Mismatch?"不一致":"未校验"),o,2);
        if(result.computed)add(field,"计算值",hex(*result.computed,4),o,2);
        append(group.children,std::move(field));
    }
    void ipv4Options(Field& header,std::size_t o,std::size_t end) {
        Field group{"选项与填充",std::to_string(end-o)+" 字节",o,end-o,{}};
        while(o<end) {
            const auto type=b[o];const bool single=type==0 || type==1;
            if(!single && (!has(o,2,end) || b[o+1]<2 || !has(o,b[o+1],end))) {
                fail("IPv4 选项长度异常");add(group,"异常选项",hex(type),o,end-o);break;
            }
            const std::size_t n=single?1:b[o+1];
            Field option{type==0?"EOL":(type==1?"NOP":(type==7?"记录路由":(type==68?"时间戳":"未知选项"))),hex(type),o,n,{}};
            add(option,"类型",std::to_string(type),o,1);
            if(!single)add(option,"长度",std::to_string(n),o+1,1);
            if(type==7) {
                if(n<3 || (n-3)%4)fail("IPv4 记录路由长度异常");
                else {
                    const auto pointer=b[o+2];add(option,"指针",std::to_string(pointer),o+2,1);
                    if(pointer<4 || pointer>n+1 || (pointer-4)%4)fail("IPv4 记录路由指针异常");
                    for(std::size_t cursor=o+3;cursor+4<=o+n;cursor+=4)add(option,"地址 "+std::to_string((cursor-o-3)/4+1),formatIp(address<4>(cursor)),cursor,4);
                }
            } else if(type==68) {
                if(n<4)fail("IPv4 时间戳长度异常");
                else {
                    const auto pointer=b[o+2];const auto flag=b[o+3]&15;const std::size_t stride=flag==0?4:8;
                    add(option,"指针",std::to_string(pointer),o+2,1);add(option,"溢出",std::to_string(b[o+3]>>4),o+3,1);add(option,"格式",std::to_string(flag),o+3,1);
                    if(flag!=0 && flag!=1 && flag!=3)fail("IPv4 时间戳格式异常");
                    else if((n-4)%stride)fail("IPv4 时间戳长度异常");
                    else {
                        if(pointer<5 || pointer>n+1 || (pointer-5)%stride)fail("IPv4 时间戳指针异常");
                        for(std::size_t cursor=o+4,index=1;cursor+stride<=o+n;cursor+=stride,++index) {
                            if(flag)add(option,"地址 "+std::to_string(index),formatIp(address<4>(cursor)),cursor,4);
                            const auto at=cursor+(flag?4:0);add(option,"时间戳 "+std::to_string(index),std::to_string(u32(at)),at,4);
                        }
                    }
                }
            } else if(!single && n>2)add(option,"数据",std::to_string(n-2)+" 字节",o+2,n-2);
            append(group.children,std::move(option));o+=n;
            if(type==0){if(o<end)add(group,"填充",std::to_string(end-o)+" 字节",o,end-o);break;}
        }
        append(header.children,std::move(group));
    }
    void icmp(std::size_t o, std::size_t end, bool fragmented,bool complete) {
        p.protocol = "ICMP";
        if(has(o,1,end))p.icmpType=b[o];
        if (!has(o,8,end)) { fail("ICMP 首部被截断"); return; }
        auto type=b[o], code=b[o+1];
        std::string label;
        switch(type) { case 8: label="回显请求"; break; case 0: label="回显应答"; break;
            case 11: label="时间超过"; break; case 3: label="目的地址不可达"; break;
            default: label="其他 ICMP"; }
        Field g{"ICMP",label,o,end-o,{}};
        add(g,"类型",std::to_string(type)+"  "+label,o,1);
        add(g,"代码",std::to_string(code),o+1,1);
        if(complete && !fragmented)p.icmpChecksum=checksum(o,end,o+2);
        checksumField(g,"检验和",o+2,p.icmpChecksum);
        if (type==0 || type==8) {
            add(g,"标识符",std::to_string(u16(o+4)),o+4,2);
            add(g,"序列号",std::to_string(u16(o+6)),o+6,2);
        } else if (type==3 || type==11) {
            add(g,"保留/类型相关字段",hex(u32(o+4),8),o+4,4);
            if(type==3 && code==4) add(g,"下一跳 MTU",std::to_string(u16(o+6)),o+6,2);
            if(type==11) add(g,"原因",code==0?"传输中 TTL 耗尽":(code==1?"分片重组超时":"未知代码"),o+1,1);
            if(type==3) {
                static const char* causes[]={"网络不可达","主机不可达","协议不可达","端口不可达","需要分片但 DF 已设置","源路由失败"};
                add(g,"原因",code<6?causes[code]:"其他不可达原因",o+1,1);
            }
            auto q=o+8;
            if(has(q,20,end) && (b[q]>>4)==4) {
                auto ihl=std::size_t(b[q]&15)*4;
                if(ihl<20 || !has(q,ihl,end)) fail("ICMP 引用的 IPv4 首部长度异常或被截断");
                else {
                    Field quote{"引用的原始 IPv4 首部","错误报文内的原始数据",q,ihl,{}};
                    add(quote,"源地址",formatIp(address<4>(q+12)),q+12,4);
                    add(quote,"目的地址",formatIp(address<4>(q+16)),q+16,4);
                    add(quote,"协议",std::to_string(b[q+9]),q+9,1);
                    append(g.children,std::move(quote));
                    if(!has(q+ihl,8,end) && !fragmented) fail("ICMP 错误报文引用的数据不足 8 字节");
                }
            } else if(!fragmented) fail("ICMP 错误报文缺少原始 IPv4 首部");
        } else add(g,"类型相关字段",hex(u32(o+4),8),o+4,4);
        if(end>o+8) add(g,"数据",std::to_string(end-o-8)+" 字节",o+8,end-o-8);
        append(p.fields,std::move(g)); p.summary=label+"  Code "+std::to_string(code);
    }
    void tcp(std::size_t o,std::size_t end,bool fragmented=false) {
        p.protocol="TCP";
        if(has(o,13,end) && (b[o+12]>>4)<5){fail("TCP 数据偏移异常");return;}
        auto partial=[&]{
            p.warnings.push_back("不完整首部");Field g{"TCP","不完整首部",o,end-o,{}};
            if(has(o,4,end)){add(g,"源端口",std::to_string(u16(o)),o,2);add(g,"目的端口",std::to_string(u16(o+2)),o+2,2);}
            if(has(o,8,end))add(g,"序列号",std::to_string(u32(o+4)),o+4,4);
            append(p.fields,std::move(g));p.summary="TCP 不完整首部";
        };
        if(!has(o,20,end)) {if(fragmented)partial();else fail("TCP 首部被截断");return;}
        auto n=std::size_t(b[o+12]>>4)*4;
        if(!has(o,n,end)) {if(fragmented)partial();else fail("TCP 选项被截断");return;}
        Field g{"TCP","传输控制协议",o,n,{}};
        add(g,"源端口",std::to_string(u16(o)),o,2); add(g,"目的端口",std::to_string(u16(o+2)),o+2,2);
        add(g,"序列号",std::to_string(u32(o+4)),o+4,4); add(g,"确认号",std::to_string(u32(o+8)),o+8,4);
        add(g,"首部长度",std::to_string(n)+" 字节",o+12,1);
        add(g,"保留位",hex((b[o+12]>>1)&7),o+12,1);
        std::string flags;
        for(auto [bit,name]:{std::pair{0x80,"CWR"},{0x40,"ECE"},{0x20,"URG"},{0x10,"ACK"},{0x08,"PSH"},{0x04,"RST"},{0x02,"SYN"},{0x01,"FIN"}})
            if(b[o+13]&bit) { if(!flags.empty()) flags+=" "; flags+=name; }
        add(g,"标志",hex(b[o+13])+" "+flags,o+12,2);
        add(g,"窗口",std::to_string(u16(o+14)),o+14,2); add(g,"检验和",hex(u16(o+16),4),o+16,2);
        add(g,"紧急指针",std::to_string(u16(o+18)),o+18,2);
        if(n>20) add(g,"选项",std::to_string(n-20)+" 字节",o+20,n-20);
        append(p.fields,std::move(g)); p.summary=std::to_string(u16(o))+" -> "+std::to_string(u16(o+2))+" ["+flags+"]";
    }
    void udp(std::size_t o,std::size_t end,bool fragmented) {
        p.protocol="UDP";
        if(!has(o,8,end)) { fail("UDP 首部被截断"); return; }
        auto n=u16(o+4);
        Field g{"UDP","用户数据报协议",o,8,{}};
        add(g,"源端口",std::to_string(u16(o)),o,2); add(g,"目的端口",std::to_string(u16(o+2)),o+2,2);
        add(g,"长度",std::to_string(n),o+4,2); add(g,"检验和",hex(u16(o+6),4),o+6,2);
        if(n<8 || (!fragmented && n>end-o)) fail("UDP 长度异常或数据被截断");
        append(p.fields,std::move(g)); p.summary=std::to_string(u16(o))+" -> "+std::to_string(u16(o+2))+"  "+std::to_string(n)+" 字节";
    }
    void ipv4(std::size_t o) {
        p.protocol="IPv4";
        if(!has(o,20,b.size())) { fail("IPv4 固定首部被截断"); return; }
        auto version=b[o]>>4; auto n=std::size_t(b[o]&15)*4; auto total=u16(o+2);
        if(version!=4 || n<20 || !has(o,n,b.size()) || total<n) { fail("IPv4 版本、首部长度或总长度异常"); return; }
        auto end=std::min(b.size(),o+total);
        if(total>b.size()-o) fail("IPv4 数据报被截断");
        p.sourceIp=address<4>(o+12); p.destinationIp=address<4>(o+16);
        p.source=formatIp(*p.sourceIp); p.destination=formatIp(*p.destinationIp);
        auto frag=u16(o+6); auto offset=frag&0x1fff; bool more=(frag&0x2000)!=0;
        Field g{"IPv4","网际协议版本 4",o,n,{}};
        add(g,"版本",std::to_string(version),o,1); add(g,"首部长度",std::to_string(n)+" 字节",o,1);
        add(g,"区分服务 DSCP",std::to_string(b[o+1]>>2),o+1,1); add(g,"ECN",std::to_string(b[o+1]&3),o+1,1);
        add(g,"总长度",std::to_string(total),o+2,2); add(g,"标识",hex(u16(o+4),4),o+4,2);
        add(g,"标志",std::string("保留=")+((frag&0x8000)?"1":"0")+" DF="+((frag&0x4000)?"1":"0")+" MF="+(more?"1":"0"),o+6,2);
        add(g,"片偏移",std::to_string(offset)+" * 8 字节",o+6,2);
        add(g,"生存时间 TTL",std::to_string(b[o+8]),o+8,1); add(g,"上层协议",std::to_string(b[o+9]),o+9,1);
        p.ipv4Checksum=checksum(o,o+n,o+10);checksumField(g,"首部检验和",o+10,p.ipv4Checksum);add(g,"源地址",p.source,o+12,4);add(g,"目的地址",p.destination,o+16,4);
        if(n>20)ipv4Options(g,o+20,o+n);
        append(p.fields,std::move(g));
        if(offset || more) p.warnings.push_back("IPv4 分片; 不进行重组");
        if(offset) { p.summary="IPv4 非首片  偏移 "+std::to_string(offset*8); return; }
        const bool complete=total<=b.size()-o;
        switch(b[o+9]) { case 1: icmp(o+n,end,more,complete); break; case 6: tcp(o+n,end,more && complete); break; case 17: udp(o+n,end,more); break;
            default: p.summary="IPv4  上层协议 "+std::to_string(b[o+9]); }
    }
    void ndOptions(Field& group,std::size_t o,std::size_t end) {
        while(o<end) {
            if(!has(o,2,end)) {fail("ICMPv6 邻居发现选项被截断");return;}
            const auto type=b[o];const auto n=std::size_t(b[o+1])*8;
            if(n==0 || !has(o,n,end)) {fail("ICMPv6 邻居发现选项长度异常或被截断");return;}
            Field option{"邻居发现选项","类型 "+std::to_string(type),o,n,{}};
            add(option,"类型",std::to_string(type),o,1);add(option,"长度",std::to_string(n)+" 字节",o+1,1);
            if(type==1 || type==2) {
                if(n!=8) fail("Ethernet 邻居发现链路地址选项长度异常");
                else add(option,type==1?"源链路地址":"目标链路地址",formatMac(address<6>(o+2)),o+2,6);
            } else if(type==3) {
                if(n!=32) fail("IPv6 前缀信息选项长度异常");
                else {
                    add(option,"前缀长度",std::to_string(b[o+2]),o+2,1);
                    add(option,"标志",hex(b[o+3]),o+3,1);
                    add(option,"有效寿命",std::to_string(u32(o+4)),o+4,4);
                    add(option,"首选寿命",std::to_string(u32(o+8)),o+8,4);
                    add(option,"前缀",formatIpv6(address<16>(o+16)),o+16,16);
                    if(b[o+2]>128) fail("IPv6 前缀长度超过 128");
                }
            } else if(type==5) {
                if(n!=8) fail("IPv6 MTU 选项长度异常");
                else add(option,"MTU",std::to_string(u32(o+4)),o+4,4);
            } else if(n>2) add(option,"选项数据",std::to_string(n-2)+" 字节",o+2,n-2);
            append(group.children,std::move(option));o+=n;
        }
    }
    void icmpv6(std::size_t o,std::size_t end,std::uint8_t hopLimit) {
        p.protocol="ICMPv6";
        if(!has(o,4,end)) {fail("ICMPv6 公共首部被截断");return;}
        const auto type=b[o],code=b[o+1];std::string label;
        switch(type) {
            case 1:label="目的地址不可达";break;case 2:label="数据包过大";break;case 3:label="时间超过";break;case 4:label="参数问题";break;
            case 128:label="回显请求";break;case 129:label="回显应答";break;
            case 133:label="路由器请求";break;case 134:label="路由器通告";break;case 135:label="邻居请求";break;
            case 136:label="邻居通告";break;case 137:label="重定向";break;default:label="其他 ICMPv6";
        }
        Field g{"ICMPv6",label,o,end-o,{}};
        add(g,"类型",std::to_string(type)+"  "+label,o,1);add(g,"代码",std::to_string(code),o+1,1);add(g,"检验和",hex(u16(o+2),4),o+2,2);
        std::size_t n=4;
        if(type<128 || type==128 || type==129 || type==133) n=8;
        else if(type==134) n=16;else if(type==135 || type==136) n=24;else if(type==137) n=40;
        if(!has(o,n,end)) {fail("ICMPv6 类型相关首部被截断");append(p.fields,std::move(g));return;}
        if(type==128 || type==129) {
            add(g,"标识符",std::to_string(u16(o+4)),o+4,2);add(g,"序列号",std::to_string(u16(o+6)),o+6,2);
        } else if(type<128) {
            add(g,type==2?"MTU":(type==4?"指针":"保留字段"),std::to_string(u32(o+4)),o+4,4);
            if(has(o+8,40,end) && (b[o+8]>>4)==6) {
                Field quote{"引用的原始 IPv6 首部","错误报文引用; 不递归解析",o+8,40,{}};
                add(quote,"源地址",formatIpv6(address<16>(o+16)),o+16,16);
                add(quote,"目的地址",formatIpv6(address<16>(o+32)),o+32,16);append(g.children,std::move(quote));
            }
        } else if(type==134) {
            add(g,"当前跳数限制",std::to_string(b[o+4]),o+4,1);add(g,"标志",hex(b[o+5]),o+5,1);
            add(g,"路由器寿命",std::to_string(u16(o+6)),o+6,2);add(g,"可达时间",std::to_string(u32(o+8)),o+8,4);add(g,"重传计时器",std::to_string(u32(o+12)),o+12,4);
        } else if(type==135 || type==136 || type==137) {
            if(type==136) add(g,"标志",std::string("R=")+((b[o+4]&128)?"1":"0")+" S="+((b[o+4]&64)?"1":"0")+" O="+((b[o+4]&32)?"1":"0"),o+4,4);
            add(g,"目标地址",formatIpv6(address<16>(o+8)),o+8,16);
            if(type==137) add(g,"重定向目的地址",formatIpv6(address<16>(o+24)),o+24,16);
        }
        if(type>=133 && type<=137) {
            if(hopLimit!=255 || code!=0) p.warnings.push_back("邻居发现报文的跳数限制应为 255、代码应为 0");
            ndOptions(g,o+n,end);
        } else if(end>o+n) add(g,"数据",std::to_string(end-o-n)+" 字节",o+n,end-o-n);
        append(p.fields,std::move(g));p.summary="ICMPv6 "+label+"  Code "+std::to_string(code);
    }
    void ipv6Options(Field& group,std::size_t o,std::size_t end) {
        while(o<end) {
            if(b[o]==0) {const auto start=o;while(o<end && b[o]==0)++o;add(group,"Pad1","填充",start,o-start);continue;}
            if(!has(o,2,end)) {fail("IPv6 选项首部被截断");return;}
            const auto n=std::size_t(b[o+1])+2;
            if(!has(o,n,end)) {fail("IPv6 选项长度超过扩展首部");return;}
            Field option{"选项","类型 "+hex(b[o]),o,n,{}};
            add(option,"类型",hex(b[o]),o,1);add(option,"数据长度",std::to_string(b[o+1]),o+1,1);
            if(n>2) add(option,"选项数据",std::to_string(n-2)+" 字节",o+2,n-2);
            append(group.children,std::move(option));o+=n;
        }
    }
    void ipv6(std::size_t o) {
        p.protocol="IPv6";
        if(!has(o,40,b.size())) {fail("IPv6 固定首部被截断");return;}
        if((b[o]>>4)!=6) {fail("IPv6 版本字段异常");return;}
        const auto payload=u16(o+4);const auto traffic=(u32(o)>>20)&255;auto next=b[o+6];const auto hop=b[o+7];
        p.sourceIpv6=address<16>(o+8);p.destinationIpv6=address<16>(o+24);
        p.source=formatIpv6(*p.sourceIpv6);p.destination=formatIpv6(*p.destinationIpv6);
        Field g{"IPv6","网际协议版本 6",o,40,{}};
        add(g,"版本","6",o,1);add(g,"流量类别",std::to_string(traffic),o,2);
        add(g,"区分服务 DSCP",std::to_string(traffic>>2),o,2);add(g,"ECN",std::to_string(traffic&3),o,2);
        add(g,"流标签",hex(u32(o)&0xfffff,5),o+1,3);add(g,"有效载荷长度",std::to_string(payload),o+4,2);
        add(g,"下一首部",std::to_string(next),o+6,1);add(g,"跳数限制",std::to_string(hop),o+7,1);
        add(g,"源地址",p.source,o+8,16);add(g,"目的地址",p.destination,o+24,16);append(p.fields,std::move(g));
        p.summary="IPv6  下一首部 "+std::to_string(next);
        if(payload==0 && next!=59) {p.warnings.push_back("有效载荷长度为 0; 不解析空载荷或 Jumbo Payload");return;}
        const auto end=std::min(b.size(),o+40+payload);
        if(payload>b.size()-o-40) fail("IPv6 有效载荷被截断");
        auto cursor=o+40;bool fragmented=false,seenFragment=false;
        for(unsigned count=0;next==0 || next==43 || next==44 || next==60 || next==51;++count) {
            if(count>=32) {fail("IPv6 扩展首部超过 32 个解析上限");return;}
            if(next==0 && cursor!=o+40) {fail("Hop-by-Hop 首部必须紧随 IPv6 基本首部");return;}
            if(!has(cursor,2,end)) {fail("IPv6 扩展首部被截断");return;}
            const auto kind=next;std::size_t n=kind==44?8:(kind==51?(std::size_t(b[cursor+1])+2)*4:(std::size_t(b[cursor+1])+1)*8);
            if((kind==51 && n<12) || !has(cursor,n,end)) {fail("IPv6 扩展首部长度异常或被截断");return;}
            const std::string name=kind==0?"Hop-by-Hop":(kind==43?"Routing":(kind==44?"Fragment":(kind==60?"Destination Options":"AH")));
            Field ext{"IPv6 "+name,name+" 扩展首部",cursor,n,{}};
            next=b[cursor];add(ext,"下一首部",std::to_string(next),cursor,1);
            if(kind==44) {
                if(seenFragment) {fail("重复 IPv6 分片首部");return;}seenFragment=true;
                const auto bits=u16(cursor+2);const auto offset=bits>>3;fragmented=(bits&1)!=0;
                add(ext,"片偏移",std::to_string(offset)+" * 8 字节",cursor+2,2);add(ext,"更多分片 M",fragmented?"1":"0",cursor+2,2);add(ext,"标识",hex(u32(cursor+4),8),cursor+4,4);
                append(p.fields,std::move(ext));
                if(offset || fragmented) p.warnings.push_back("IPv6 分片; 不进行重组");
                if(offset) {p.summary="IPv6 非首片  偏移 "+std::to_string(offset*8);return;}
            } else {
                add(ext,"首部长度",std::to_string(n)+" 字节",cursor+1,1);
                if(kind==0 || kind==60) ipv6Options(ext,cursor+2,cursor+n);
                else if(kind==43) {
                    add(ext,"路由类型",std::to_string(b[cursor+2]),cursor+2,1);add(ext,"剩余段数",std::to_string(b[cursor+3]),cursor+3,1);
                    add(ext,"类型相关数据",std::to_string(n-4)+" 字节",cursor+4,n-4);
                } else {
                    add(ext,"SPI",hex(u32(cursor+4),8),cursor+4,4);add(ext,"序列号",std::to_string(u32(cursor+8)),cursor+8,4);
                    if(n>12) add(ext,"完整性校验值",std::to_string(n-12)+" 字节（未验证）",cursor+12,n-12);
                }
                append(p.fields,std::move(ext));if(!p.error.empty()) return;
            }
            cursor+=n;
        }
        switch(next) {
            case 6:tcp(cursor,end);break;case 17:udp(cursor,end,fragmented);break;case 58:icmpv6(cursor,end,hop);break;
            case 59:p.summary="IPv6  无下一首部";break;
            case 50:
                p.summary="IPv6  ESP 加密载荷";p.warnings.push_back("ESP 加密数据不解密，不推断上层协议");
                if(!has(cursor,8,end)) fail("ESP 首部被截断");
                else {Field esp{"ESP","封装安全载荷（未解密）",cursor,end-cursor,{}};add(esp,"SPI",hex(u32(cursor),8),cursor,4);add(esp,"序列号",std::to_string(u32(cursor+4)),cursor+4,4);append(p.fields,std::move(esp));}break;
            default:p.summary="IPv6  未解析的下一首部 "+std::to_string(next);p.warnings.push_back("不支持的 IPv6 上层协议; 保留原始字节");
        }
    }
    void arp(std::size_t o) {
        p.protocol="ARP";
        if(!has(o,8,b.size())) { fail("ARP 固定首部被截断"); return; }
        auto h=b[o+4], a=b[o+5]; auto n=std::size_t(8)+2*(std::size_t(h)+a);
        if(!has(o,n,b.size())) { fail("ARP 地址字段被截断"); return; }
        Field g{"ARP","地址解析协议",o,n,{}};
        add(g,"硬件类型",std::to_string(u16(o)),o,2); add(g,"协议类型",hex(u16(o+2),4),o+2,2);
        add(g,"硬件地址长度",std::to_string(h),o+4,1); add(g,"协议地址长度",std::to_string(a),o+5,1);
        add(g,"操作",std::to_string(u16(o+6)),o+6,2);
        if(h==6 && a==4 && u16(o)==1 && u16(o+2)==0x0800) {
            add(g,"发送者 MAC",formatMac(address<6>(o+8)),o+8,6);
            add(g,"发送者 IP",formatIp(address<4>(o+14)),o+14,4);
            add(g,"目标 MAC",formatMac(address<6>(o+18)),o+18,6);
            add(g,"目标 IP",formatIp(address<4>(o+24)),o+24,4);
            p.summary=(u16(o+6)==1?"查询 ":(u16(o+6)==2?"应答 ":"操作 "))+formatIp(address<4>(o+24));
        } else p.summary="ARP  非 Ethernet/IPv4 地址格式";
        append(p.fields,std::move(g));
    }
    Packet run() {
        if(p.raw.originalLength<p.raw.bytes.size()) fail("原始长度小于捕获长度");
        if(p.raw.linkType!=1) { p.protocol="其他链路"; fail("不支持的链路类型 "+std::to_string(p.raw.linkType)+"; 仅解析 Ethernet"); return std::move(p); }
        if(!has(0,14,b.size())) { fail("Ethernet 首部被截断"); return std::move(p); }
        p.destinationMac=address<6>(0); p.sourceMac=address<6>(6);
        p.source=formatMac(*p.sourceMac); p.destination=formatMac(*p.destinationMac);
        auto type=u16(12); std::size_t o=14;
        Field g{"Ethernet II","以太网帧",0,14,{}};
        add(g,"目的 MAC",p.destination,0,6); add(g,"源 MAC",p.source,6,6); add(g,"类型/长度",hex(type,4),12,2);
        add(g,"捕获长度",std::to_string(b.size())+" 字节",0,0);
        add(g,"原始长度",std::to_string(p.raw.originalLength)+" 字节",0,0);
        add(g,"数据字段",std::to_string(b.size()-14)+" 字节（捕获内容）",14,b.size()-14);
        add(g,"FCS","未捕获或无法确认，不作推断",0,0);
        append(p.fields,std::move(g));
        if(type==0x8100) {
            if(!has(14,4,b.size())) { fail("802.1Q VLAN 标记被截断"); return std::move(p); }
            auto tci=u16(14); Field vlan{"802.1Q","VLAN "+std::to_string(tci&0xfff),14,4,{}};
            add(vlan,"优先级 PCP",std::to_string(tci>>13),14,2); add(vlan,"DEI",std::to_string((tci>>12)&1),14,2);
            add(vlan,"VLAN ID",std::to_string(tci&0xfff),14,2); type=u16(16); add(vlan,"封装类型",hex(type,4),16,2);
            append(p.fields,std::move(vlan)); o=18;
        }
        if(type==0x0800) ipv4(o);
        else if(type==0x0806) arp(o);
        else if(type==0x86dd) ipv6(o);
        else p.summary="EtherType "+hex(type,4)+"  保留原始数据";
        if(p.raw.originalLength>b.size()) p.warnings.push_back("捕获长度小于原始帧长");
        return std::move(p);
    }
};
}
std::string formatMac(const std::array<std::uint8_t,6>& a) {
    constexpr char digits[]="0123456789ABCDEF";
    std::string result(17,':');
    for(std::size_t i=0;i<a.size();++i) {
        result[i*3]=digits[a[i]>>4];
        result[i*3+1]=digits[a[i]&15];
    }
    return result;
}
std::string formatIp(const std::array<std::uint8_t,4>& a) {
    std::array<char,15> buffer{};
    auto* out=buffer.data();
    for(std::size_t i=0;i<a.size();++i) {
        if(i)*out++='.';
        out=std::to_chars(out,buffer.data()+buffer.size(),a[i]).ptr;
    }
    return {buffer.data(),static_cast<std::size_t>(out-buffer.data())};
}
std::string formatIpv6(const std::array<std::uint8_t,16>& a) {
    std::array<unsigned,8> words{};for(std::size_t i=0;i<8;++i) words[i]=(unsigned(a[2*i])<<8)|a[2*i+1];
    std::size_t best=8,length=0;
    for(std::size_t i=0;i<8;) {
        if(words[i]) {++i;continue;}const auto start=i;while(i<8 && words[i]==0) ++i;
        if(i-start>=2 && i-start>length) {best=start;length=i-start;}
    }
    std::array<char,39> buffer{};
    auto* out=buffer.data();
    for(std::size_t i=0;i<8;) {
        if(i==best) {
            *out++=':';*out++=':';i+=length;
        } else {
            if(i>0 && i!=best+length)*out++=':';
            out=std::to_chars(out,buffer.data()+buffer.size(),words[i++],16).ptr;
        }
    }
    return {buffer.data(),static_cast<std::size_t>(out-buffer.data())};
}
std::size_t estimatePacketBytes(const Packet& packet) {
    auto stringBytes=[](const std::string& value){
        const auto data=reinterpret_cast<std::uintptr_t>(value.data()),object=reinterpret_cast<std::uintptr_t>(&value);
        return data>=object && data<object+sizeof(value)?std::size_t(0):value.capacity()+1;
    };
    auto fieldsBytes=[&](auto&& self,const std::vector<Field>& fields)->std::size_t {
        std::size_t total=fields.capacity()*sizeof(Field);
        for(const auto& field:fields)total+=stringBytes(field.name)+stringBytes(field.value)+self(self,field.children);
        return total;
    };
    std::size_t total=sizeof(Packet)+32+packet.raw.bytes.capacity()+packet.warnings.capacity()*sizeof(std::string);
    for(const auto* value:{&packet.protocol,&packet.source,&packet.destination,&packet.summary,&packet.error})total+=stringBytes(*value);
    for(const auto& warning:packet.warnings)total+=stringBytes(warning);
    return total+fieldsBytes(fieldsBytes,packet.fields);
}
Packet decodePacket(RawPacket raw) {auto packet=Decoder(std::move(raw)).run();packet.estimatedBytes=estimatePacketBytes(packet);return packet;}
}
