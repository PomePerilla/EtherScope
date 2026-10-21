#pragma once
#include "core/tcp_conversations.h"
#include <memory>
#include <stop_token>

namespace etherscope {
class SessionStore;
inline constexpr std::size_t streamInputLimit = 16 * 1024 * 1024, streamPacketLimit = 10000;
inline constexpr std::size_t streamDirectionLimit = 1024 * 1024, streamPieceLimit = 4096,
                             streamEventLimit = 1024;
inline constexpr std::int64_t streamSequenceWindow = 64 * 1024 * 1024;
struct TcpStreamRequest {
    std::uint64_t conversationId{}, generation{};
    TcpKey key;
    std::array<std::optional<std::uint32_t>, 2> start, end;
    std::vector<std::shared_ptr<const Packet>> packets;
    bool cachePartial{}, inputLimited{};
};
std::optional<TcpStreamRequest> snapshotTcpStream(const SessionStore &store, std::uint64_t id);
enum class StreamEventKind { Duplicate, Overlap, GapAhead, GapFilled, Conflict };
struct StreamEvent {
    StreamEventKind kind{};
    unsigned direction{};
    std::uint64_t packetId{}, relatedPacketId{};
    std::uint32_t sequence{}, length{};
};
struct StreamBlock {
    std::uint32_t sequence{}, length{};
    std::uint64_t packetId{};
    // Empty bytes denote a gap. Data blocks retain first-observed bytes.
    std::vector<std::uint8_t> bytes;
};
struct StreamDirection {
    std::vector<StreamBlock> blocks;
    std::uint64_t uniqueBytes{}, duplicateSegments{}, overlapSegments{}, gapAheadSegments{},
        gapFilledSegments{}, conflictBytes{}, skippedSegments{};
    std::size_t gaps{};
    bool startKnown{}, prefixMissing{}, suffixMissing{}, boundaryConflict{}, limited{};
};
struct TcpStreamResult {
    std::array<StreamDirection, 2> directions;
    std::vector<StreamEvent> events;
    std::uint64_t conversationId{}, generation{}, firstPacket{}, lastPacket{}, eventsOmitted{};
    std::size_t inputPackets{}, inputRawBytes{}, estimatedBytes{};
    bool cachePartial{}, inputLimited{}, cancelled{};
};
TcpStreamResult reassembleTcp(const TcpStreamRequest &request, std::stop_token stop = {});
} // namespace etherscope
