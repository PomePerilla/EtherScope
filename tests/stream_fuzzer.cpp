#include "core/tcp_stream.h"
#include <algorithm>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    using namespace etherscope;
    if (size < 5 || size > 65540)
        return 0;
    auto word = [&](std::size_t at) {
        return std::uint32_t(data[at]) | (std::uint32_t(data[at + 1]) << 8) |
               (std::uint32_t(data[at + 2]) << 16) | (std::uint32_t(data[at + 3]) << 24);
    };
    const auto base = word(0);
    TcpStreamRequest request;
    request.conversationId = 1;
    request.generation = 1;
    request.cachePartial = (data[4] & 4) != 0;
    request.key.a.address = {192, 0, 2, 1};
    request.key.a.port = 50000;
    request.key.b.address = {192, 0, 2, 2};
    request.key.b.port = 443;
    if (data[4] & 1)
        request.start[0] = base;
    if (data[4] & 2)
        request.start[1] = base;
    std::size_t cursor = 5;
    while (cursor + 7 <= size) {
        const bool reverse = (data[cursor] & 1) != 0;
        const auto sequence = base + word(cursor + 1);
        const auto flags = data[cursor + 5];
        const auto length = std::min<std::size_t>(data[cursor + 6], size - cursor - 7);
        cursor += 7;
        auto packet = std::make_shared<Packet>();
        packet->id = request.packets.size() + 1;
        packet->tcpConversationId = 1;
        packet->protocol = "TCP";
        packet->sourceIp = reverse ? std::array<std::uint8_t, 4>{192, 0, 2, 2}
                                   : std::array<std::uint8_t, 4>{192, 0, 2, 1};
        packet->destinationIp = reverse ? std::array<std::uint8_t, 4>{192, 0, 2, 1}
                                        : std::array<std::uint8_t, 4>{192, 0, 2, 2};
        packet->raw.bytes.assign(data + cursor, data + cursor + length);
        packet->raw.originalLength = static_cast<std::uint32_t>(length);
        packet->tcp = TcpInfo{std::uint16_t(reverse ? 443 : 50000),
                              std::uint16_t(reverse ? 50000 : 443),
                              sequence,
                              0,
                              static_cast<std::uint32_t>(length),
                              std::uint8_t(flags & 31),
                              !(flags & 64),
                              std::uint32_t(flags & 128 ? length + 1 : 0)};
        request.packets.push_back(std::move(packet));
        cursor += length;
    }
    const auto result = reassembleTcp(request);
    if (result.events.size() > streamEventLimit || result.inputPackets > streamPacketLimit ||
        result.inputRawBytes > streamInputLimit || result.estimatedBytes > 8 * 1024 * 1024)
        std::abort();
    for (const auto &direction : result.directions) {
        std::size_t bytes = 0, gaps = 0;
        std::optional<std::uint32_t> next;
        for (const auto &block : direction.blocks) {
            if (!block.length || (next && block.sequence != *next))
                std::abort();
            next = block.sequence + block.length;
            if (block.bytes.empty()) {
                ++gaps;
                if (block.packetId)
                    std::abort();
            } else {
                if (block.length != block.bytes.size() || !block.packetId ||
                    block.packetId > request.packets.size())
                    std::abort();
                bytes += block.bytes.size();
            }
        }
        if (bytes != direction.uniqueBytes || bytes > streamDirectionLimit ||
            gaps != direction.gaps || direction.blocks.size() > 2 * streamPieceLimit + 1)
            std::abort();
    }
    return 0;
}
