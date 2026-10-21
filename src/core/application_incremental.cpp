#include "core/application_analyzer.h"
#include "core/application_buffer.h"
#include "core/application_stream.h"
#include "core/tcp_stream_internal.h"
#include <algorithm>
#include <map>

namespace etherscope {
namespace {
using Bytes = std::vector<std::uint8_t>;
struct Piece {
    Bytes bytes;
    std::uint64_t packet{};
    std::size_t rawOffset{};
};
class SequenceStream {
  public:
    bool incomplete{}, limited{}, startKnown{}, endKnown{};
    std::uint64_t delivered{};
    void boundaries(std::optional<std::uint32_t> start, std::optional<std::uint32_t> end) {
        if (start && !startKnown) {
            if (!anchor_) {
                anchor_ = *start;
                next_ = 0;
            } else if (const auto at = absolute(*start)) {
                if (delivered && *at != 0)
                    incomplete = true;
                else if (!delivered)
                    next_ = *at;
            } else {
                limited = true;
            }
            startKnown = true;
        }
        end_ = end;
    }
    void insert(const Packet &packet, std::stop_token stop) {
        const auto &tcp = *packet.tcp;
        if (!tcp.completeSegment || !packet.error.empty() || ((tcp.flags & 2) && (tcp.flags & 5)) ||
            ((tcp.flags & 1) && (tcp.flags & 4)) ||
            !containsBytes(packet.raw.bytes.size(), tcp.payloadOffset, tcp.payloadLength)) {
            incomplete = true;
            return;
        }
        if (!tcp.payloadLength)
            return;
        const auto sequence = tcp.sequence + ((tcp.flags & 2) ? 1u : 0u);
        if (!anchor_)
            anchor_ = sequence;
        const auto first = absolute(sequence);
        if (!first || *first > next_ + streamSequenceWindow ||
            *first + tcp.payloadLength < next_ - streamSequenceWindow) {
            limited = true;
            return;
        }
        const auto last = *first + tcp.payloadLength;
        auto at = *first;
        auto found = pieces_.upper_bound(at);
        if (found != pieces_.begin()) {
            const auto previous = std::prev(found);
            if (previous->first + static_cast<std::int64_t>(previous->second.bytes.size()) > at)
                found = previous;
        }
        while (at < last && !stop.stop_requested()) {
            if (found != pieces_.end() && found->first <= at) {
                const auto end = std::min(
                    last, found->first + static_cast<std::int64_t>(found->second.bytes.size()));
                for (auto position = at; position < end; ++position) {
                    if ((position - at) % 4096 == 0 && stop.stop_requested())
                        return;
                    if (packet.raw.bytes[tcp.payloadOffset +
                                         static_cast<std::size_t>(position - *first)] !=
                        found->second.bytes[static_cast<std::size_t>(position - found->first)])
                        incomplete = true;
                }
                at = end;
                ++found;
            } else {
                const auto end = found == pieces_.end() ? last : std::min(last, found->first);
                const auto count = static_cast<std::size_t>(end - at);
                if (at < next_) {
                    // Retransmissions older than the comparison window are never parsed again.
                    incomplete = true;
                    at = std::min(end, next_);
                    continue;
                }
                trimHistory();
                if (pieces_.size() >= streamPieceLimit || count > streamDirectionLimit - bytes_) {
                    limited = true;
                    return;
                }
                Piece piece;
                piece.packet = packet.id;
                piece.rawOffset = tcp.payloadOffset + static_cast<std::size_t>(at - *first);
                piece.bytes.assign(packet.raw.bytes.begin() +
                                       static_cast<std::ptrdiff_t>(piece.rawOffset),
                                   packet.raw.bytes.begin() +
                                       static_cast<std::ptrdiff_t>(piece.rawOffset + count));
                bytes_ += count;
                pieces_.emplace(at, std::move(piece));
                at = end;
            }
        }
    }
    ApplicationInput take(unsigned side) {
        ApplicationInput input;
        input.direction = side;
        input.startKnown = startKnown;
        input.source = DataSource::Reassembled;
        input.incomplete = incomplete || limited;
        auto bytes = std::make_shared<Bytes>();
        if (startKnown) {
            for (;;) {
                auto found = pieces_.upper_bound(next_);
                if (found == pieces_.begin())
                    break;
                --found;
                const auto offset = static_cast<std::size_t>(next_ - found->first);
                if (offset >= found->second.bytes.size())
                    break;
                const auto count = found->second.bytes.size() - offset;
                input.sources.push_back(
                    {found->second.packet, found->second.rawOffset + offset, count, bytes->size()});
                bytes->insert(bytes->end(),
                              found->second.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                              found->second.bytes.end());
                next_ += static_cast<std::int64_t>(count);
                delivered += count;
            }
        }
        input.bytes = std::move(bytes);
        endKnown = false;
        if (end_ && anchor_) {
            const auto end = absolute(*end_);
            endKnown = end && *end == next_;
            if (end && *end < next_)
                incomplete = true;
        }
        input.endKnown = endKnown;
        trimHistory();
        return input;
    }
    bool awaiting() const {
        if (!startKnown && !pieces_.empty())
            return true;
        if (!pieces_.empty() &&
            pieces_.rbegin()->first +
                    static_cast<std::int64_t>(pieces_.rbegin()->second.bytes.size()) >
                next_)
            return true;
        return end_ && !endKnown;
    }
    std::size_t estimatedBytes() const {
        return sizeof(*this) + bytes_ +
               pieces_.size() * (sizeof(Piece) + sizeof(std::int64_t) + 64);
    }

  private:
    std::map<std::int64_t, Piece> pieces_;
    std::optional<std::uint32_t> anchor_, end_;
    std::int64_t next_{};
    std::size_t bytes_{};
    std::optional<std::int64_t> absolute(std::uint32_t sequence) const {
        if (!anchor_)
            return {};
        const auto difference =
            detail::sequenceDistance(sequence, *anchor_ + static_cast<std::uint32_t>(next_));
        return difference ? std::optional(next_ + *difference) : std::nullopt;
    }
    void trimHistory() {
        while (!pieces_.empty()) {
            const auto first = pieces_.begin();
            const auto end = first->first + static_cast<std::int64_t>(first->second.bytes.size());
            if (end > next_ || (next_ - end <= 65536 && pieces_.size() < streamPieceLimit / 2))
                break;
            bytes_ -= first->second.bytes.size();
            pieces_.erase(first);
        }
    }
};
void mergeResults(ApplicationResult &target, const ApplicationResult &source) {
    auto priority = [](AnalysisStatus status) {
        switch (status) {
        case AnalysisStatus::Limited:
            return 6;
        case AnalysisStatus::AuthenticationFailed:
            return 5;
        case AnalysisStatus::MissingKeys:
            return 4;
        case AnalysisStatus::Unsupported:
            return 3;
        case AnalysisStatus::Incomplete:
            return 2;
        case AnalysisStatus::Pending:
            return 1;
        default:
            return 0;
        }
    };
    if (priority(source.status) > priority(target.status)) {
        target.status = source.status;
        target.error = source.error;
    }
    for (const auto &message : source.messages)
        appendApplicationMessage(target, message);
}
} // namespace

struct ConversationAnalysis::Impl {
    enum class Protocol { Unknown, Dns, Http1, Http2, Tls, Other };
    Protocol protocol{Protocol::Unknown}, plaintextProtocol{Protocol::Unknown};
    std::array<SequenceStream, 2> streams;
    std::array<detail::ApplicationBuffer, 2> sniff, plaintextSniff, dns;
    std::unique_ptr<Http1Stream> http1, plaintextHttp1;
    std::unique_ptr<Http2Stream> http2, plaintextHttp2;
    std::unique_ptr<TlsStream> tls;
    ApplicationResult dnsResult;
    ApplicationResult lastResult;
    std::uint64_t lastPacket{}, dnsDropped{}, retentionFloor{};
    bool limited{};

    Protocol identify(const std::array<detail::ApplicationBuffer, 2> &buffers, bool encrypted) {
        bool data = false;
        for (const auto &buffer : buffers) {
            const auto &bytes = *buffer.data.bytes;
            if (bytes.empty())
                continue;
            data = true;
            const std::string_view text(reinterpret_cast<const char *>(bytes.data()), bytes.size());
            constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            if (text.size() < preface.size() && preface.starts_with(text))
                return Protocol::Unknown;
            if (text.starts_with(preface))
                return Protocol::Http2;
            if (!encrypted && bytes.size() >= 3 && bytes[0] >= 20 && bytes[0] <= 23 &&
                bytes[1] == 3)
                return Protocol::Tls;
            if (text.starts_with("HTTP/1.") || text.find(" HTTP/1.") != std::string_view::npos)
                return Protocol::Http1;
            if (!buffer.data.endKnown && bytes.size() < applicationHeaderLimit &&
                text.find('\n') == std::string_view::npos)
                return Protocol::Unknown;
        }
        return data ? Protocol::Other : Protocol::Unknown;
    }
    ApplicationResult application(const std::array<ApplicationInput, 2> &input, bool plaintext,
                                  std::string_view alpn, std::stop_token stop) {
        auto &selected = plaintext ? plaintextProtocol : protocol;
        auto &buffers = plaintext ? plaintextSniff : sniff;
        auto &first = plaintext ? plaintextHttp1 : http1;
        auto &second = plaintext ? plaintextHttp2 : http2;
        std::array<ApplicationInput, 2> bytes = input;
        if (selected == Protocol::Unknown) {
            for (unsigned side = 0; side < 2; ++side)
                buffers[side].append(input[side]);
            selected = alpn == "h2" ? Protocol::Http2 : identify(buffers, plaintext);
            if (selected == Protocol::Unknown) {
                ApplicationResult pending;
                if (buffers[0].size() || buffers[1].size())
                    pending.status = AnalysisStatus::Pending;
                return pending;
            }
            for (unsigned side = 0; side < 2; ++side) {
                bytes[side] = buffers[side].data;
                buffers[side].consume(buffers[side].size());
            }
        }
        if (selected == Protocol::Http1) {
            if (!first)
                first = std::make_unique<Http1Stream>();
            return first->append(bytes, stop);
        }
        if (selected == Protocol::Http2) {
            if (!second)
                second = std::make_unique<Http2Stream>();
            return second->append(bytes, stop);
        }
        if (selected == Protocol::Tls) {
            // The caller routes TLS to the record parser after classification.
            for (unsigned side = 0; side < 2; ++side)
                sniff[side].append(bytes[side]);
        }
        return {};
    }
};
ConversationAnalysis::ConversationAnalysis() : impl_(std::make_unique<Impl>()) {}
ConversationAnalysis::~ConversationAnalysis() = default;
ApplicationResult ConversationAnalysis::append(const TcpStreamRequest &request,
                                               const TlsKeyLog &keys, std::stop_token stop) {
    auto &state = *impl_;
    ApplicationResult result;
    try {
        if (state.limited) {
            result = state.lastResult;
            result.status = AnalysisStatus::Limited;
            return result;
        }
        for (unsigned side = 0; side < 2; ++side)
            state.streams[side].boundaries(request.start[side], request.end[side]);
        auto pump = [&] {
            std::array<ApplicationInput, 2> input;
            for (unsigned side = 0; side < 2; ++side)
                input[side] = state.streams[side].take(side);
            if (request.key.a.port == 53 || request.key.b.port == 53) {
                state.protocol = Impl::Protocol::Dns;
                for (unsigned side = 0; side < 2; ++side) {
                    auto &buffer = state.dns[side];
                    buffer.append(input[side]);
                    while (buffer.size() >= 2 && !stop.stop_requested()) {
                        ByteView view(*buffer.data.bytes);
                        const auto length = static_cast<std::size_t>(view.integer(0, 2));
                        if (!length)
                            throw std::runtime_error("Invalid DNS message length");
                        if (buffer.size() - 2 < length || !buffer.data.startKnown)
                            break;
                        auto parsed = decodeDns(buffer.data, 2, length);
                        for (auto &message : parsed.messages)
                            detail::freezeMessage(message, buffer.base);
                        if (parsed.status != AnalysisStatus::Complete) {
                            state.dnsResult.status = parsed.status;
                            state.dnsResult.error = parsed.error;
                        }
                        for (auto &message : parsed.messages)
                            detail::appendStreamMessage(state.dnsResult, std::move(message),
                                                        state.dnsDropped);
                        buffer.consume(length + 2);
                    }
                }
                result = state.dnsResult;
                if (state.dnsDropped && state.dnsDropped >= state.retentionFloor)
                    result.status = AnalysisStatus::Limited;
                if ((state.dns[0].size() || state.dns[1].size()) &&
                    result.status == AnalysisStatus::Complete)
                    result.status = AnalysisStatus::Incomplete;
            } else {
                if (state.protocol != Impl::Protocol::Tls)
                    result = state.application(input, false, {}, stop);
                if (state.protocol == Impl::Protocol::Tls) {
                    if (!state.tls) {
                        state.tls = std::make_unique<TlsStream>();
                        for (unsigned side = 0; side < 2; ++side) {
                            input[side] = state.sniff[side].data;
                            state.sniff[side].consume(state.sniff[side].size());
                        }
                    }
                    auto decoded = state.tls->append(input, keys, stop);
                    result = std::move(decoded.analysis);
                    // The plaintext parser receives this update's authenticated bytes exactly once.
                    auto application =
                        state.application(decoded.plaintext, true, decoded.alpn, stop);
                    mergeResults(result, application);
                }
            }
        };
        std::size_t pendingBytes = 0, pendingPackets = 0;
        for (const auto &packet : request.packets) {
            if (stop.stop_requested())
                break;
            if (!packet || packet->id <= state.lastPacket)
                continue;
            state.lastPacket = packet->id;
            pendingBytes += packet->tcp ? packet->tcp->payloadLength : 0;
            ++pendingPackets;
            if (!packet->tcp || packet->tcpConversationId != request.conversationId)
                continue;
            if (const auto side = detail::streamDirection(*packet, request.key))
                state.streams[*side].insert(*packet, stop);
            if (pendingBytes >= 65536 || pendingPackets >= 32) {
                pump();
                pendingBytes = pendingPackets = 0;
            }
        }
        pump();
        for (const auto &stream : state.streams) {
            if (stream.limited)
                result.status = AnalysisStatus::Limited;
            else if ((stream.incomplete || stream.awaiting()) &&
                     result.status == AnalysisStatus::Complete)
                result.status = AnalysisStatus::Incomplete;
        }
        if (request.inputLimited)
            result.status = AnalysisStatus::Limited;
    } catch (const std::length_error &error) {
        state.limited = true;
        if (result.messages.empty())
            result = state.lastResult;
        result.status = AnalysisStatus::Limited;
        result.error = error.what();
    } catch (const std::exception &error) {
        result.status = AnalysisStatus::Incomplete;
        result.error = error.what();
    }
    result.estimatedBytes = estimateApplicationBytes(result);
    state.lastResult = result;
    return result;
}
void ConversationAnalysis::prune(std::uint64_t first) {
    auto &state = *impl_;
    state.retentionFloor = first;
    detail::pruneMessages(state.dnsResult, first);
    detail::pruneMessages(state.lastResult, first);
    if (state.http1)
        state.http1->prune(first);
    if (state.http2)
        state.http2->prune(first);
    if (state.tls)
        state.tls->prune(first);
    if (state.plaintextHttp1)
        state.plaintextHttp1->prune(first);
    if (state.plaintextHttp2)
        state.plaintextHttp2->prune(first);
}
bool ConversationAnalysis::keysChanged(const TlsKeyLog &previous, const TlsKeyLog &next) const {
    if (!impl_->tls)
        return false;
    const auto random = impl_->tls->clientRandom();
    if (!random)
        return false;
    for (const auto label :
         {"CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
          "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"}) {
        const auto old = previous.find(*random, label), current = next.find(*random, label);
        if (bool(old) != bool(current) || (old && *old != *current))
            return true;
    }
    return false;
}
std::size_t ConversationAnalysis::estimatedBytes() const {
    const auto &state = *impl_;
    std::size_t bytes = sizeof(Impl) + estimateApplicationBytes(state.dnsResult);
    bytes += estimateApplicationBytes(state.lastResult);
    for (unsigned side = 0; side < 2; ++side)
        bytes += state.streams[side].estimatedBytes() + state.sniff[side].estimatedBytes() +
                 state.plaintextSniff[side].estimatedBytes() + state.dns[side].estimatedBytes();
    if (state.http1)
        bytes += state.http1->estimatedBytes();
    if (state.http2)
        bytes += state.http2->estimatedBytes();
    if (state.tls)
        bytes += state.tls->estimatedBytes();
    if (state.plaintextHttp1)
        bytes += state.plaintextHttp1->estimatedBytes();
    if (state.plaintextHttp2)
        bytes += state.plaintextHttp2->estimatedBytes();
    return bytes;
}
std::uint64_t ConversationAnalysis::deliveredBytes() const {
    return impl_->streams[0].delivered + impl_->streams[1].delivered;
}
} // namespace etherscope
