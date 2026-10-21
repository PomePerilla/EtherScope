// Decoder methods share bounds checks and field accounting with packet.cpp.
void icmp(std::size_t o, std::size_t end, bool fragmented, bool complete) {
    p.protocol = "ICMP";
    if (has(o, 1, end))
        p.icmpType = b[o];
    if (!has(o, 8, end)) {
        fail("ICMP 首部被截断");
        return;
    }
    auto type = b[o], code = b[o + 1];
    std::string label;
    switch (type) {
    case 8:
        label = "回显请求";
        break;
    case 0:
        label = "回显应答";
        break;
    case 11:
        label = "时间超过";
        break;
    case 3:
        label = "目的地址不可达";
        break;
    default:
        label = "其他 ICMP";
    }
    auto g = node([&] { return Field{"ICMP", label, o, end - o, {}}; });
    emitField(g, [&] { return Field{"类型", std::to_string(type) + "  " + label, o, 1, {}}; });
    emitField(g, [&] { return Field{"代码", std::to_string(code), o + 1, 1, {}}; });
    if (complete && !fragmented)
        p.icmpChecksum = checksum(o, end, o + 2);
    checksumField(g, "检验和", o + 2, p.icmpChecksum);
    if (type == 0 || type == 8) {
        emitField(g, [&] { return Field{"标识符", std::to_string(u16(o + 4)), o + 4, 2, {}}; });
        emitField(g, [&] { return Field{"序列号", std::to_string(u16(o + 6)), o + 6, 2, {}}; });
    } else if (type == 3 || type == 11) {
        emitField(g, [&] { return Field{"保留/类型相关字段", hex(u32(o + 4), 8), o + 4, 4, {}}; });
        if (type == 3 && code == 4)
            emitField(
                g, [&] { return Field{"下一跳 MTU", std::to_string(u16(o + 6)), o + 6, 2, {}}; });
        if (type == 11)
            emitField(g, [&] {
                return Field{"原因",
                             code == 0 ? "传输中 TTL 耗尽"
                                       : (code == 1 ? "分片重组超时" : "未知代码"),
                             o + 1,
                             1,
                             {}};
            });
        if (type == 3) {
            static const char *causes[] = {"网络不可达", "主机不可达",           "协议不可达",
                                           "端口不可达", "需要分片但 DF 已设置", "源路由失败"};
            emitField(g, [&] {
                return Field{"原因", code < 6 ? causes[code] : "其他不可达原因", o + 1, 1, {}};
            });
        }
        auto q = o + 8;
        if (has(q, 20, end) && (b[q] >> 4) == 4) {
            auto ihl = std::size_t(b[q] & 15) * 4;
            if (ihl < 20 || !has(q, ihl, end))
                fail("ICMP 引用的 IPv4 首部长度异常或被截断");
            else {
                auto quote = node([&] {
                    return Field{"引用的原始 IPv4 首部", "错误报文内的原始数据", q, ihl, {}};
                });
                emitField(quote, [&] {
                    return Field{"源地址", formatIp(address<4>(q + 12)), q + 12, 4, {}};
                });
                emitField(quote, [&] {
                    return Field{"目的地址", formatIp(address<4>(q + 16)), q + 16, 4, {}};
                });
                emitField(quote,
                          [&] { return Field{"协议", std::to_string(b[q + 9]), q + 9, 1, {}}; });
                append(g, std::move(quote));
                if (!has(q + ihl, 8, end) && !fragmented)
                    fail("ICMP 错误报文引用的数据不足 8 字节");
            }
        } else if (!fragmented)
            fail("ICMP 错误报文缺少原始 IPv4 首部");
    } else
        emitField(g, [&] { return Field{"类型相关字段", hex(u32(o + 4), 8), o + 4, 4, {}}; });
    if (end > o + 8)
        emitField(g, [&] {
            return Field{"数据", std::to_string(end - o - 8) + " 字节", o + 8, end - o - 8, {}};
        });
    append(root_, std::move(g));
    p.summary = label + "  Code " + std::to_string(code);
}
void tcp(std::size_t o, std::size_t end, bool partialFragment = false,
         bool completeSegment = true) {
    p.protocol = "TCP";
    if (has(o, 13, end) && (b[o + 12] >> 4) < 5) {
        fail("TCP 数据偏移异常");
        return;
    }
    auto partial = [&] {
        p.warnings.push_back("不完整首部");
        auto g = node([&] { return Field{"TCP", "不完整首部", o, end - o, {}}; });
        if (has(o, 4, end)) {
            emitField(g, [&] { return Field{"源端口", std::to_string(u16(o)), o, 2, {}}; });
            emitField(g,
                      [&] { return Field{"目的端口", std::to_string(u16(o + 2)), o + 2, 2, {}}; });
        }
        if (has(o, 8, end))
            emitField(g, [&] { return Field{"序列号", std::to_string(u32(o + 4)), o + 4, 4, {}}; });
        append(root_, std::move(g));
        p.summary = "TCP 不完整首部";
    };
    if (!has(o, 20, end)) {
        if (partialFragment)
            partial();
        else
            fail("TCP 首部被截断");
        return;
    }
    auto n = std::size_t(b[o + 12] >> 4) * 4;
    if (!has(o, n, end)) {
        if (partialFragment)
            partial();
        else
            fail("TCP 选项被截断");
        return;
    }
    p.tcp = TcpInfo{u16(o),
                    u16(o + 2),
                    u32(o + 4),
                    u32(o + 8),
                    static_cast<std::uint32_t>(end - o - n),
                    b[o + 13],
                    completeSegment,
                    static_cast<std::uint32_t>(o + n)};
    auto g = node([&] { return Field{"TCP", "传输控制协议", o, n, {}}; });
    emitField(g, [&] { return Field{"源端口", std::to_string(u16(o)), o, 2, {}}; });
    emitField(g, [&] { return Field{"目的端口", std::to_string(u16(o + 2)), o + 2, 2, {}}; });
    emitField(g, [&] { return Field{"序列号", std::to_string(u32(o + 4)), o + 4, 4, {}}; });
    emitField(g, [&] { return Field{"确认号", std::to_string(u32(o + 8)), o + 8, 4, {}}; });
    emitField(g, [&] { return Field{"首部长度", std::to_string(n) + " 字节", o + 12, 1, {}}; });
    emitField(g, [&] { return Field{"保留位", hex((b[o + 12] >> 1) & 7), o + 12, 1, {}}; });
    std::string flags;
    for (auto [bit, name] : {std::pair{0x80, "CWR"},
                             {0x40, "ECE"},
                             {0x20, "URG"},
                             {0x10, "ACK"},
                             {0x08, "PSH"},
                             {0x04, "RST"},
                             {0x02, "SYN"},
                             {0x01, "FIN"}})
        if (b[o + 13] & bit) {
            if (!flags.empty())
                flags += " ";
            flags += name;
        }
    emitField(g, [&] { return Field{"标志", hex(b[o + 13]) + " " + flags, o + 12, 2, {}}; });
    emitField(g, [&] { return Field{"窗口", std::to_string(u16(o + 14)), o + 14, 2, {}}; });
    emitField(g, [&] { return Field{"检验和", hex(u16(o + 16), 4), o + 16, 2, {}}; });
    emitField(g, [&] { return Field{"紧急指针", std::to_string(u16(o + 18)), o + 18, 2, {}}; });
    if (n > 20)
        emitField(
            g, [&] { return Field{"选项", std::to_string(n - 20) + " 字节", o + 20, n - 20, {}}; });
    append(root_, std::move(g));
    p.summary = std::to_string(u16(o)) + " -> " + std::to_string(u16(o + 2)) + " [" + flags + "]";
}
void udp(std::size_t o, std::size_t end, bool fragmented) {
    p.protocol = "UDP";
    if (!has(o, 8, end)) {
        fail("UDP 首部被截断");
        return;
    }
    auto n = u16(o + 4);
    auto g = node([&] { return Field{"UDP", "用户数据报协议", o, 8, {}}; });
    emitField(g, [&] { return Field{"源端口", std::to_string(u16(o)), o, 2, {}}; });
    emitField(g, [&] { return Field{"目的端口", std::to_string(u16(o + 2)), o + 2, 2, {}}; });
    emitField(g, [&] { return Field{"长度", std::to_string(n), o + 4, 2, {}}; });
    emitField(g, [&] { return Field{"检验和", hex(u16(o + 6), 4), o + 6, 2, {}}; });
    if (n < 8 || (!fragmented && n > end - o))
        fail("UDP 长度异常或数据被截断");
    if (n >= 8)
        p.udp = UdpInfo{u16(o), u16(o + 2), static_cast<std::uint32_t>(o + 8),
                        static_cast<std::uint32_t>(std::min<std::size_t>(n, end - o) - 8),
                        !fragmented && n <= end - o};
    append(root_, std::move(g));
    p.summary = std::to_string(u16(o)) + " -> " + std::to_string(u16(o + 2)) + "  " +
                std::to_string(n) + " 字节";
}
