// Decoder methods share bounds checks and field accounting with packet.cpp.
void ipv4Options(Node &header, std::size_t o, std::size_t end) {
    auto group = node(
        [&] { return Field{"选项与填充", std::to_string(end - o) + " 字节", o, end - o, {}}; });
    while (o < end) {
        const auto type = b[o];
        const bool single = type == 0 || type == 1;
        if (!single && (!has(o, 2, end) || b[o + 1] < 2 || !has(o, b[o + 1], end))) {
            fail("IPv4 选项长度异常");
            emitField(group, [&] { return Field{"异常选项", hex(type), o, end - o, {}}; });
            break;
        }
        const std::size_t n = single ? 1 : b[o + 1];
        auto option = node([&] {
            return Field{
                type == 0
                    ? "EOL"
                    : (type == 1 ? "NOP"
                                 : (type == 7 ? "记录路由" : (type == 68 ? "时间戳" : "未知选项"))),
                hex(type),
                o,
                n,
                {}};
        });
        emitField(option, [&] { return Field{"类型", std::to_string(type), o, 1, {}}; });
        if (!single)
            emitField(option, [&] { return Field{"长度", std::to_string(n), o + 1, 1, {}}; });
        if (type == 7) {
            if (n < 3 || (n - 3) % 4)
                fail("IPv4 记录路由长度异常");
            else {
                const auto pointer = b[o + 2];
                emitField(option,
                          [&] { return Field{"指针", std::to_string(pointer), o + 2, 1, {}}; });
                if (pointer < 4 || pointer > n + 1 || (pointer - 4) % 4)
                    fail("IPv4 记录路由指针异常");
                for (std::size_t cursor = o + 3; cursor + 4 <= o + n; cursor += 4)
                    emitField(option, [&] {
                        return Field{"地址 " + std::to_string((cursor - o - 3) / 4 + 1),
                                     formatIp(address<4>(cursor)),
                                     cursor,
                                     4,
                                     {}};
                    });
            }
        } else if (type == 68) {
            if (n < 4)
                fail("IPv4 时间戳长度异常");
            else {
                const auto pointer = b[o + 2];
                const auto flag = b[o + 3] & 15;
                const std::size_t stride = flag == 0 ? 4 : 8;
                emitField(option,
                          [&] { return Field{"指针", std::to_string(pointer), o + 2, 1, {}}; });
                emitField(option, [&] {
                    return Field{"溢出", std::to_string(b[o + 3] >> 4), o + 3, 1, {}};
                });
                emitField(option,
                          [&] { return Field{"格式", std::to_string(flag), o + 3, 1, {}}; });
                if (flag != 0 && flag != 1 && flag != 3)
                    fail("IPv4 时间戳格式异常");
                else if ((n - 4) % stride)
                    fail("IPv4 时间戳长度异常");
                else {
                    if (pointer < 5 || pointer > n + 1 || (pointer - 5) % stride)
                        fail("IPv4 时间戳指针异常");
                    for (std::size_t cursor = o + 4, index = 1; cursor + stride <= o + n;
                         cursor += stride, ++index) {
                        if (flag)
                            emitField(option, [&] {
                                return Field{"地址 " + std::to_string(index),
                                             formatIp(address<4>(cursor)),
                                             cursor,
                                             4,
                                             {}};
                            });
                        const auto at = cursor + (flag ? 4 : 0);
                        emitField(option, [&] {
                            return Field{"时间戳 " + std::to_string(index),
                                         std::to_string(u32(at)),
                                         at,
                                         4,
                                         {}};
                        });
                    }
                }
            }
        } else if (!single && n > 2)
            emitField(option, [&] {
                return Field{"数据", std::to_string(n - 2) + " 字节", o + 2, n - 2, {}};
            });
        append(group, std::move(option));
        o += n;
        if (type == 0) {
            if (o < end)
                emitField(group, [&] {
                    return Field{"填充", std::to_string(end - o) + " 字节", o, end - o, {}};
                });
            break;
        }
    }
    append(header, std::move(group));
}
