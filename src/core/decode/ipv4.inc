// Decoder methods share bounds checks and field accounting with packet.cpp.
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
        auto g=node([&]{return Field{"IPv4","网际协议版本 4",o,n,{}};});
        emitField(g,[&]{return Field{"版本",std::to_string(version),o,1,{}};}); emitField(g,[&]{return Field{"首部长度",std::to_string(n)+" 字节",o,1,{}};});
        emitField(g,[&]{return Field{"区分服务 DSCP",std::to_string(b[o+1]>>2),o+1,1,{}};}); emitField(g,[&]{return Field{"ECN",std::to_string(b[o+1]&3),o+1,1,{}};});
        emitField(g,[&]{return Field{"总长度",std::to_string(total),o+2,2,{}};}); emitField(g,[&]{return Field{"标识",hex(u16(o+4),4),o+4,2,{}};});
        emitField(g,[&]{return Field{"标志",std::string("保留=")+((frag&0x8000)?"1":"0")+" DF="+((frag&0x4000)?"1":"0")+" MF="+(more?"1":"0"),o+6,2,{}};});
        emitField(g,[&]{return Field{"片偏移",std::to_string(offset)+" * 8 字节",o+6,2,{}};});
        emitField(g,[&]{return Field{"生存时间 TTL",std::to_string(b[o+8]),o+8,1,{}};}); emitField(g,[&]{return Field{"上层协议",std::to_string(b[o+9]),o+9,1,{}};});
        p.ipv4Checksum=checksum(o,o+n,o+10);checksumField(g,"首部检验和",o+10,p.ipv4Checksum);emitField(g,[&]{return Field{"源地址",p.source,o+12,4,{}};});emitField(g,[&]{return Field{"目的地址",p.destination,o+16,4,{}};});
        if(n>20)ipv4Options(g,o+20,o+n);
        append(root_,std::move(g));
        if(offset || more) p.warnings.push_back("IPv4 分片; 不进行重组");
        if(offset) { p.summary="IPv4 非首片  偏移 "+std::to_string(offset*8); return; }
        const bool complete=total<=b.size()-o;
        switch(b[o+9]) { case 1: icmp(o+n,end,more,complete); break; case 6: tcp(o+n,end,more && complete,complete && !more); break; case 17: udp(o+n,end,more); break;
            default: p.summary="IPv4  上层协议 "+std::to_string(b[o+9]); }
    }
