#include "core/tcp_stream.h"
#include "core/tcp_stream_internal.h"
#include "core/session.h"
#include <algorithm>
#include <map>
#include <span>

namespace etherscope {
namespace {
struct Piece {
    std::span<const std::uint8_t> bytes;
    std::uint64_t packetId;
};
struct Direction {
    std::map<std::int64_t, Piece> pieces;
    std::optional<std::uint32_t> anchor;
    std::optional<std::int64_t> beginning;
    std::int64_t low{}, high{}, frontier{};
};
using detail::sequenceDistance;
std::optional<unsigned> directionOf(const Packet &packet, const TcpStreamRequest &request) {
    return detail::streamDirection(packet, request.key);
}
void addEvent(TcpStreamResult &result, StreamEventKind kind, unsigned direction,
              const Packet &packet, std::uint64_t related = 0) {
    if (result.events.size() >= streamEventLimit) {
        ++result.eventsOmitted;
        return;
    }
    const auto sequence = packet.tcp->sequence + ((packet.tcp->flags & 2) ? 1u : 0u);
    result.events.push_back(
        {kind, direction, packet.id, related, sequence, packet.tcp->payloadLength});
}
void appendGap(StreamDirection &output, std::int64_t start, std::int64_t end,
               std::uint32_t anchor) {
    if (end <= start)
        return;
    output.blocks.push_back({anchor + static_cast<std::uint32_t>(start),
                             static_cast<std::uint32_t>(end - start),
                             0,
                             {}});
    ++output.gaps;
}
} // namespace
std::optional<TcpStreamRequest> snapshotTcpStream(const SessionStore &store, std::uint64_t id) {
    const auto *connection = store.tcp().find(id);
    if (!connection)
        return {};
    TcpStreamRequest request;
    request.conversationId = id;
    request.generation = store.tcp().generation();
    request.key = connection->key;
    for (unsigned side = 0; side < 2; ++side) {
        if (connection->syn[side].seen)
            request.start[side] = connection->syn[side].sequence + 1;
        if (connection->finNext[side])
            request.end[side] = *connection->finNext[side] - 1;
    }
    if (connection->initiator >= 0 && connection->synAck.seen)
        request.start[1u - static_cast<unsigned>(connection->initiator)] =
            connection->synAck.sequence + 1;
    std::size_t bytes = 0;
    for (const auto &packet : store.packets())
        if (packet->tcpConversationId == id) {
            if (request.packets.size() >= streamPacketLimit ||
                packet->raw.bytes.size() > streamInputLimit - bytes) {
                request.inputLimited = true;
                break;
            }
            bytes += packet->raw.bytes.size();
            request.packets.push_back(packet);
        }
    request.cachePartial =
        request.packets.size() != connection->packets[0] + connection->packets[1];
    return request;
}
TcpStreamResult reassembleTcp(const TcpStreamRequest &request, std::stop_token stop) {
    TcpStreamResult result;
    result.conversationId = request.conversationId;
    result.generation = request.generation;
    result.cachePartial = request.cachePartial;
    result.inputLimited = request.inputLimited;
    std::array<Direction, 2> directions;
    auto starts = request.start, ends = request.end;
    std::size_t visited = 0;
    for (const auto &pointer : request.packets) {
        if (stop.stop_requested()) {
            result.cancelled = true;
            return result;
        }
        if (visited++ >= streamPacketLimit) {
            result.inputLimited = true;
            break;
        }
        if (!pointer)
            continue;
        const auto &packet = *pointer;
        if (result.inputPackets >= streamPacketLimit ||
            packet.raw.bytes.size() > streamInputLimit - result.inputRawBytes) {
            result.inputLimited = true;
            break;
        }
        ++result.inputPackets;
        result.inputRawBytes += packet.raw.bytes.size();
        if (!result.firstPacket)
            result.firstPacket = packet.id;
        result.lastPacket = packet.id;
        if (packet.tcpConversationId != request.conversationId || !packet.tcp ||
            packet.protocol != "TCP")
            continue;
        const auto side = directionOf(packet, request);
        if (!side)
            continue;
        auto &output = result.directions[*side];
        auto &d = directions[*side];
        const auto &t = *packet.tcp;
        if (!t.completeSegment || !packet.error.empty() || ((t.flags & 2) && (t.flags & 5)) ||
            ((t.flags & 1) && (t.flags & 4)) || t.payloadOffset > packet.raw.bytes.size() ||
            t.payloadLength > packet.raw.bytes.size() - t.payloadOffset) {
            ++output.skippedSegments;
            continue;
        }
        if ((t.flags & 2) && !starts[*side])
            starts[*side] = t.sequence + 1;
        if ((t.flags & 1) && !ends[*side])
            ends[*side] = t.sequence + t.payloadLength;
        if (!t.payloadLength)
            continue;
        const auto sequence = t.sequence + ((t.flags & 2) ? 1u : 0u);
        if (!d.anchor) {
            d.anchor = sequence;
            d.low = d.high = d.frontier = 0;
            if (starts[*side]) {
                const auto begin = sequenceDistance(*starts[*side], sequence);
                if (begin && *begin <= 0 && *begin >= -streamSequenceWindow) {
                    d.beginning = *begin;
                    d.frontier = *begin;
                }
            }
        }
        const auto relativeStart = sequenceDistance(sequence, *d.anchor);
        if (!relativeStart || std::max(d.high, *relativeStart + std::int64_t(t.payloadLength)) -
                                      std::min(d.low, *relativeStart) >
                                  streamSequenceWindow) {
            output.limited = true;
            ++output.skippedSegments;
            continue;
        }
        const auto start = *relativeStart, end = start + t.payloadLength;
        const auto priorHigh = d.high;
        const auto priorLow = d.beginning.value_or(d.low);
        const bool hadData = !d.pieces.empty();
        const bool ahead = start > d.frontier;
        const auto bytes = std::span<const std::uint8_t>(packet.raw.bytes)
                               .subspan(t.payloadOffset, t.payloadLength);
        std::size_t matched = 0, conflicts = 0, inserted = 0;
        std::uint64_t related = 0, conflictOwner = 0;
        bool filled = false, limited = false;
        auto cursor = start;
        auto it = d.pieces.upper_bound(start);
        if (it != d.pieces.begin()) {
            auto previous = std::prev(it);
            if (previous->first + static_cast<std::int64_t>(previous->second.bytes.size()) > start)
                it = previous;
        }
        while (cursor < end) {
            if (stop.stop_requested()) {
                result.cancelled = true;
                return result;
            }
            if (it != d.pieces.end() && it->first <= cursor) {
                const auto stopAt =
                    std::min(end, it->first + static_cast<std::int64_t>(it->second.bytes.size()));
                if (!related)
                    related = it->second.packetId;
                for (auto offset = cursor; offset < stopAt; ++offset) {
                    if ((offset - cursor) % 4096 == 0 && stop.stop_requested()) {
                        result.cancelled = true;
                        return result;
                    }
                    if (bytes[static_cast<std::size_t>(offset - start)] ==
                        it->second.bytes[static_cast<std::size_t>(offset - it->first)])
                        ++matched;
                    else {
                        ++conflicts;
                        if (!conflictOwner)
                            conflictOwner = it->second.packetId;
                    }
                }
                cursor = stopAt;
                ++it;
            } else {
                const auto stopAt = it == d.pieces.end() ? end : std::min(end, it->first);
                auto length = static_cast<std::size_t>(stopAt - cursor);
                if (d.pieces.size() >= streamPieceLimit ||
                    output.uniqueBytes >= streamDirectionLimit) {
                    limited = true;
                    break;
                }
                length = std::min(length, streamDirectionLimit -
                                              static_cast<std::size_t>(output.uniqueBytes));
                if ((hadData || d.beginning) && cursor < priorHigh &&
                    cursor + static_cast<std::int64_t>(length) > priorLow)
                    filled = true;
                d.pieces.emplace(
                    cursor, Piece{bytes.subspan(static_cast<std::size_t>(cursor - start), length),
                                  packet.id});
                inserted += length;
                output.uniqueBytes += length;
                cursor += static_cast<std::int64_t>(length);
                if (cursor < stopAt) {
                    limited = true;
                    break;
                }
            }
        }
        if (inserted) {
            d.low = d.pieces.begin()->first;
            d.high = std::max(
                d.high, d.pieces.rbegin()->first +
                            static_cast<std::int64_t>(d.pieces.rbegin()->second.bytes.size()));
            if (ahead) {
                ++output.gapAheadSegments;
                addEvent(result, StreamEventKind::GapAhead, *side, packet);
            }
            if (filled) {
                ++output.gapFilledSegments;
                addEvent(result, StreamEventKind::GapFilled, *side, packet);
            }
            for (auto contiguous = d.pieces.upper_bound(d.frontier);;) {
                if (contiguous != d.pieces.begin()) {
                    const auto previous = std::prev(contiguous);
                    const auto next =
                        previous->first + static_cast<std::int64_t>(previous->second.bytes.size());
                    if (previous->first <= d.frontier && next > d.frontier) {
                        d.frontier = next;
                        contiguous = d.pieces.upper_bound(d.frontier);
                        continue;
                    }
                }
                break;
            }
        }
        if (limited)
            output.limited = true;
        if (conflicts) {
            output.conflictBytes += conflicts;
            addEvent(result, StreamEventKind::Conflict, *side, packet, conflictOwner);
        } else if (matched && !inserted && !limited) {
            ++output.duplicateSegments;
            addEvent(result, StreamEventKind::Duplicate, *side, packet, related);
        } else if (matched && inserted) {
            ++output.overlapSegments;
            addEvent(result, StreamEventKind::Overlap, *side, packet, related);
        }
    }
    for (unsigned side = 0; side < 2; ++side) {
        auto &output = result.directions[side];
        const auto &d = directions[side];
        output.startKnown = starts[side].has_value();
        if (!d.anchor || d.pieces.empty()) {
            if (starts[side] && ends[side]) {
                const auto length = sequenceDistance(*ends[side], *starts[side]);
                if (!length || *length > streamSequenceWindow)
                    output.limited = true;
                else if (*length < 0)
                    output.boundaryConflict = true;
                else if (*length > 0) {
                    appendGap(output, 0, *length, *starts[side]);
                    output.prefixMissing = output.suffixMissing = true;
                }
            }
            continue;
        }
        auto cursor = d.pieces.begin()->first;
        if (starts[side]) {
            const auto beginning = sequenceDistance(*starts[side], *d.anchor);
            output.prefixMissing = !beginning || *beginning < cursor;
            output.boundaryConflict = beginning && *beginning > cursor;
            if (beginning && *beginning < cursor && cursor - *beginning <= streamSequenceWindow)
                cursor = *beginning;
        }
        for (const auto &[offset, piece] : d.pieces) {
            if (stop.stop_requested()) {
                result.cancelled = true;
                return result;
            }
            appendGap(output, cursor, offset, *d.anchor);
            StreamBlock block{*d.anchor + static_cast<std::uint32_t>(offset),
                              static_cast<std::uint32_t>(piece.bytes.size()),
                              piece.packetId,
                              {}};
            block.bytes.assign(piece.bytes.begin(), piece.bytes.end());
            output.blocks.push_back(std::move(block));
            cursor = offset + static_cast<std::int64_t>(piece.bytes.size());
        }
        if (ends[side]) {
            const auto ending = sequenceDistance(*ends[side], *d.anchor);
            output.suffixMissing = !ending || *ending > cursor;
            output.boundaryConflict = output.boundaryConflict || (ending && *ending < cursor);
            if (ending && *ending > cursor && *ending - cursor <= streamSequenceWindow)
                appendGap(output, cursor, *ending, *d.anchor);
        }
    }
    result.estimatedBytes = sizeof(result) + result.events.capacity() * sizeof(StreamEvent);
    for (const auto &output : result.directions) {
        result.estimatedBytes += output.blocks.capacity() * sizeof(StreamBlock);
        for (const auto &block : output.blocks)
            result.estimatedBytes += block.bytes.capacity();
    }
    return result;
}
} // namespace etherscope
