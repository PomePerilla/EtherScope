// Decoder methods share bounds checks and field accounting with packet.cpp.
    void ndOptions(Node& group,std::size_t o,std::size_t end) {
        while(o<end) {
            if(!has(o,2,end)) {fail("ICMPv6 邻居发现选项被截断");return;}
            const auto type=b[o];const auto n=std::size_t(b[o+1])*8;
            if(n==0 || !has(o,n,end)) {fail("ICMPv6 邻居发现选项长度异常或被截断");return;}
            auto option=node([&]{return Field{"邻居发现选项","类型 "+std::to_string(type),o,n,{}};});
            emitField(option,[&]{return Field{"类型",std::to_string(type),o,1,{}};});emitField(option,[&]{return Field{"长度",std::to_string(n)+" 字节",o+1,1,{}};});
            if(type==1 || type==2) {
                if(n!=8) fail("Ethernet 邻居发现链路地址选项长度异常");
                else emitField(option,[&]{return Field{type==1?"源链路地址":"目标链路地址",formatMac(address<6>(o+2)),o+2,6,{}};});
            } else if(type==3) {
                if(n!=32) fail("IPv6 前缀信息选项长度异常");
                else {
                    emitField(option,[&]{return Field{"前缀长度",std::to_string(b[o+2]),o+2,1,{}};});
                    emitField(option,[&]{return Field{"标志",hex(b[o+3]),o+3,1,{}};});
                    emitField(option,[&]{return Field{"有效寿命",std::to_string(u32(o+4)),o+4,4,{}};});
                    emitField(option,[&]{return Field{"首选寿命",std::to_string(u32(o+8)),o+8,4,{}};});
                    emitField(option,[&]{return Field{"前缀",formatIpv6(address<16>(o+16)),o+16,16,{}};});
                    if(b[o+2]>128) fail("IPv6 前缀长度超过 128");
                }
            } else if(type==5) {
                if(n!=8) fail("IPv6 MTU 选项长度异常");
                else emitField(option,[&]{return Field{"MTU",std::to_string(u32(o+4)),o+4,4,{}};});
            } else if(n>2) emitField(option,[&]{return Field{"选项数据",std::to_string(n-2)+" 字节",o+2,n-2,{}};});
            append(group,std::move(option));o+=n;
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
        auto g=node([&]{return Field{"ICMPv6",label,o,end-o,{}};});
        emitField(g,[&]{return Field{"类型",std::to_string(type)+"  "+label,o,1,{}};});emitField(g,[&]{return Field{"代码",std::to_string(code),o+1,1,{}};});emitField(g,[&]{return Field{"检验和",hex(u16(o+2),4),o+2,2,{}};});
        std::size_t n=4;
        if(type<128 || type==128 || type==129 || type==133) n=8;
        else if(type==134) n=16;else if(type==135 || type==136) n=24;else if(type==137) n=40;
        if(!has(o,n,end)) {fail("ICMPv6 类型相关首部被截断");append(root_,std::move(g));return;}
        if(type==128 || type==129) {
            emitField(g,[&]{return Field{"标识符",std::to_string(u16(o+4)),o+4,2,{}};});emitField(g,[&]{return Field{"序列号",std::to_string(u16(o+6)),o+6,2,{}};});
        } else if(type<128) {
            emitField(g,[&]{return Field{type==2?"MTU":(type==4?"指针":"保留字段"),std::to_string(u32(o+4)),o+4,4,{}};});
            if(has(o+8,40,end) && (b[o+8]>>4)==6) {
                auto quote=node([&]{return Field{"引用的原始 IPv6 首部","错误报文引用; 不递归解析",o+8,40,{}};});
                emitField(quote,[&]{return Field{"源地址",formatIpv6(address<16>(o+16)),o+16,16,{}};});
                emitField(quote,[&]{return Field{"目的地址",formatIpv6(address<16>(o+32)),o+32,16,{}};});append(g,std::move(quote));
            }
        } else if(type==134) {
            emitField(g,[&]{return Field{"当前跳数限制",std::to_string(b[o+4]),o+4,1,{}};});emitField(g,[&]{return Field{"标志",hex(b[o+5]),o+5,1,{}};});
            emitField(g,[&]{return Field{"路由器寿命",std::to_string(u16(o+6)),o+6,2,{}};});emitField(g,[&]{return Field{"可达时间",std::to_string(u32(o+8)),o+8,4,{}};});emitField(g,[&]{return Field{"重传计时器",std::to_string(u32(o+12)),o+12,4,{}};});
        } else if(type==135 || type==136 || type==137) {
            if(type==136) emitField(g,[&]{return Field{"标志",std::string("R=")+((b[o+4]&128)?"1":"0")+" S="+((b[o+4]&64)?"1":"0")+" O="+((b[o+4]&32)?"1":"0"),o+4,4,{}};});
            emitField(g,[&]{return Field{"目标地址",formatIpv6(address<16>(o+8)),o+8,16,{}};});
            if(type==137) emitField(g,[&]{return Field{"重定向目的地址",formatIpv6(address<16>(o+24)),o+24,16,{}};});
        }
        if(type>=133 && type<=137) {
            if(hopLimit!=255 || code!=0) p.warnings.push_back("邻居发现报文的跳数限制应为 255、代码应为 0");
            ndOptions(g,o+n,end);
        } else if(end>o+n) emitField(g,[&]{return Field{"数据",std::to_string(end-o-n)+" 字节",o+n,end-o-n,{}};});
        append(root_,std::move(g));p.summary="ICMPv6 "+label+"  Code "+std::to_string(code);
    }
    void ipv6Options(Node& group,std::size_t o,std::size_t end) {
        while(o<end) {
            if(b[o]==0) {const auto start=o;while(o<end && b[o]==0)++o;emitField(group,[&]{return Field{"Pad1","填充",start,o-start,{}};});continue;}
            if(!has(o,2,end)) {fail("IPv6 选项首部被截断");return;}
            const auto n=std::size_t(b[o+1])+2;
            if(!has(o,n,end)) {fail("IPv6 选项长度超过扩展首部");return;}
            auto option=node([&]{return Field{"选项","类型 "+hex(b[o]),o,n,{}};});
            emitField(option,[&]{return Field{"类型",hex(b[o]),o,1,{}};});emitField(option,[&]{return Field{"数据长度",std::to_string(b[o+1]),o+1,1,{}};});
            if(n>2) emitField(option,[&]{return Field{"选项数据",std::to_string(n-2)+" 字节",o+2,n-2,{}};});
            append(group,std::move(option));o+=n;
        }
    }
    void ipv6(std::size_t o) {
        p.protocol="IPv6";
        if(!has(o,40,b.size())) {fail("IPv6 固定首部被截断");return;}
        if((b[o]>>4)!=6) {fail("IPv6 版本字段异常");return;}
        const auto payload=u16(o+4);const auto traffic=(u32(o)>>20)&255;auto next=b[o+6];const auto hop=b[o+7];
        p.sourceIpv6=address<16>(o+8);p.destinationIpv6=address<16>(o+24);
        p.source=formatIpv6(*p.sourceIpv6);p.destination=formatIpv6(*p.destinationIpv6);
        auto g=node([&]{return Field{"IPv6","网际协议版本 6",o,40,{}};});
        emitField(g,[&]{return Field{"版本","6",o,1,{}};});emitField(g,[&]{return Field{"流量类别",std::to_string(traffic),o,2,{}};});
        emitField(g,[&]{return Field{"区分服务 DSCP",std::to_string(traffic>>2),o,2,{}};});emitField(g,[&]{return Field{"ECN",std::to_string(traffic&3),o,2,{}};});
        emitField(g,[&]{return Field{"流标签",hex(u32(o)&0xfffff,5),o+1,3,{}};});emitField(g,[&]{return Field{"有效载荷长度",std::to_string(payload),o+4,2,{}};});
        emitField(g,[&]{return Field{"下一首部",std::to_string(next),o+6,1,{}};});emitField(g,[&]{return Field{"跳数限制",std::to_string(hop),o+7,1,{}};});
        emitField(g,[&]{return Field{"源地址",p.source,o+8,16,{}};});emitField(g,[&]{return Field{"目的地址",p.destination,o+24,16,{}};});append(root_,std::move(g));
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
            auto ext=node([&]{return Field{"IPv6 "+name,name+" 扩展首部",cursor,n,{}};});
            next=b[cursor];emitField(ext,[&]{return Field{"下一首部",std::to_string(next),cursor,1,{}};});
            if(kind==44) {
                if(seenFragment) {fail("重复 IPv6 分片首部");return;}seenFragment=true;
                const auto bits=u16(cursor+2);const auto offset=bits>>3;fragmented=(bits&1)!=0;
                emitField(ext,[&]{return Field{"片偏移",std::to_string(offset)+" * 8 字节",cursor+2,2,{}};});emitField(ext,[&]{return Field{"更多分片 M",fragmented?"1":"0",cursor+2,2,{}};});emitField(ext,[&]{return Field{"标识",hex(u32(cursor+4),8),cursor+4,4,{}};});
                append(root_,std::move(ext));
                if(offset || fragmented) p.warnings.push_back("IPv6 分片; 不进行重组");
                if(offset) {p.summary="IPv6 非首片  偏移 "+std::to_string(offset*8);return;}
            } else {
                emitField(ext,[&]{return Field{"首部长度",std::to_string(n)+" 字节",cursor+1,1,{}};});
                if(kind==0 || kind==60) ipv6Options(ext,cursor+2,cursor+n);
                else if(kind==43) {
                    emitField(ext,[&]{return Field{"路由类型",std::to_string(b[cursor+2]),cursor+2,1,{}};});emitField(ext,[&]{return Field{"剩余段数",std::to_string(b[cursor+3]),cursor+3,1,{}};});
                    emitField(ext,[&]{return Field{"类型相关数据",std::to_string(n-4)+" 字节",cursor+4,n-4,{}};});
                } else {
                    emitField(ext,[&]{return Field{"SPI",hex(u32(cursor+4),8),cursor+4,4,{}};});emitField(ext,[&]{return Field{"序列号",std::to_string(u32(cursor+8)),cursor+8,4,{}};});
                    if(n>12) emitField(ext,[&]{return Field{"完整性校验值",std::to_string(n-12)+" 字节（未验证）",cursor+12,n-12,{}};});
                }
                append(root_,std::move(ext));if(!p.error.empty()) return;
            }
            cursor+=n;
        }
        switch(next) {
            case 6:tcp(cursor,end,false,!fragmented && payload<=b.size()-o-40);break;case 17:udp(cursor,end,fragmented);break;case 58:icmpv6(cursor,end,hop);break;
            case 59:p.summary="IPv6  无下一首部";break;
            case 50:
                p.summary="IPv6  ESP 加密载荷";p.warnings.push_back("ESP 加密数据不解密，不推断上层协议");
                if(!has(cursor,8,end)) fail("ESP 首部被截断");
                else {auto esp=node([&]{return Field{"ESP","封装安全载荷（未解密）",cursor,end-cursor,{}};});emitField(esp,[&]{return Field{"SPI",hex(u32(cursor),8),cursor,4,{}};});emitField(esp,[&]{return Field{"序列号",std::to_string(u32(cursor+4)),cursor+4,4,{}};});append(root_,std::move(esp));}break;
            default:p.summary="IPv6  未解析的下一首部 "+std::to_string(next);p.warnings.push_back("不支持的 IPv6 上层协议; 保留原始字节");
        }
    }
