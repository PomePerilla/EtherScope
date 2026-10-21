// Decoder methods share bounds checks and field accounting with packet.cpp.
    void arp(std::size_t o) {
        p.protocol="ARP";
        if(!has(o,8,b.size())) { fail("ARP 固定首部被截断"); return; }
        auto h=b[o+4], a=b[o+5]; auto n=std::size_t(8)+2*(std::size_t(h)+a);
        if(!has(o,n,b.size())) { fail("ARP 地址字段被截断"); return; }
        auto g=node([&]{return Field{"ARP","地址解析协议",o,n,{}};});
        emitField(g,[&]{return Field{"硬件类型",std::to_string(u16(o)),o,2,{}};}); emitField(g,[&]{return Field{"协议类型",hex(u16(o+2),4),o+2,2,{}};});
        emitField(g,[&]{return Field{"硬件地址长度",std::to_string(h),o+4,1,{}};}); emitField(g,[&]{return Field{"协议地址长度",std::to_string(a),o+5,1,{}};});
        emitField(g,[&]{return Field{"操作",std::to_string(u16(o+6)),o+6,2,{}};});
        if(h==6 && a==4 && u16(o)==1 && u16(o+2)==0x0800) {
            emitField(g,[&]{return Field{"发送者 MAC",formatMac(address<6>(o+8)),o+8,6,{}};});
            emitField(g,[&]{return Field{"发送者 IP",formatIp(address<4>(o+14)),o+14,4,{}};});
            emitField(g,[&]{return Field{"目标 MAC",formatMac(address<6>(o+18)),o+18,6,{}};});
            emitField(g,[&]{return Field{"目标 IP",formatIp(address<4>(o+24)),o+24,4,{}};});
            p.summary=(u16(o+6)==1?"查询 ":(u16(o+6)==2?"应答 ":"操作 "))+formatIp(address<4>(o+24));
        } else p.summary="ARP  非 Ethernet/IPv4 地址格式";
        append(root_,std::move(g));
    }
    Packet run() {
        if(p.raw.originalLength<b.size()) fail("原始长度小于捕获长度");
        if(p.raw.linkType!=1) { p.protocol="其他链路";p.summary="Link type "+std::to_string(p.raw.linkType);p.warnings.push_back("Unsupported link type");return std::move(p); }
        if(!has(0,14,b.size())) { fail("Ethernet 首部被截断"); return std::move(p); }
        p.destinationMac=address<6>(0); p.sourceMac=address<6>(6);
        p.source=formatMac(*p.sourceMac); p.destination=formatMac(*p.destinationMac);
        auto type=u16(12); std::size_t o=14;
        auto g=node([&]{return Field{"Ethernet II","以太网帧",0,14,{}};});
        emitField(g,[&]{return Field{"目的 MAC",p.destination,0,6,{}};}); emitField(g,[&]{return Field{"源 MAC",p.source,6,6,{}};}); emitField(g,[&]{return Field{"类型/长度",hex(type,4),12,2,{}};});
        emitField(g,[&]{return Field{"捕获长度",std::to_string(b.size())+" 字节",0,0,{}};});
        emitField(g,[&]{return Field{"原始长度",std::to_string(p.raw.originalLength)+" 字节",0,0,{}};});
        emitField(g,[&]{return Field{"数据字段",std::to_string(b.size()-14)+" 字节（捕获内容）",14,b.size()-14,{}};});
        emitField(g,[&]{return Field{"FCS","未捕获或无法确认，不作推断",0,0,{}};});
        append(root_,std::move(g));
        if(type==0x8100) {
            if(!has(14,4,b.size())) { fail("802.1Q VLAN 标记被截断"); return std::move(p); }
            auto tci=u16(14);p.vlanId=tci&0xfff;auto vlan=node([&]{return Field{"802.1Q","VLAN "+std::to_string(tci&0xfff),14,4,{}};});
            emitField(vlan,[&]{return Field{"优先级 PCP",std::to_string(tci>>13),14,2,{}};}); emitField(vlan,[&]{return Field{"DEI",std::to_string((tci>>12)&1),14,2,{}};});
            emitField(vlan,[&]{return Field{"VLAN ID",std::to_string(tci&0xfff),14,2,{}};}); type=u16(16); emitField(vlan,[&]{return Field{"封装类型",hex(type,4),16,2,{}};});
            append(root_,std::move(vlan)); o=18;
        }
        if(type==0x0800) ipv4(o);
        else if(type==0x0806) arp(o);
        else if(type==0x86dd) ipv6(o);
        else p.summary="EtherType "+hex(type,4)+"  保留原始数据";
        if(p.raw.originalLength>b.size()) p.warnings.push_back("捕获长度小于原始帧长");
        return std::move(p);
    }