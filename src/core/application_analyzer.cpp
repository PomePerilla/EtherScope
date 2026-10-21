#include "core/application_analyzer.h"
#include "core/bytes.h"
#include <algorithm>
#include <cctype>
#include <set>

namespace etherscope {
namespace {
void merge(ApplicationResult &target, ApplicationResult source) {
    if (source.status != AnalysisStatus::Complete) {
        target.status = source.status;
        if (!source.error.empty())
            target.error = std::move(source.error);
    }
    try {
        for (auto &message : source.messages)
            appendApplicationMessage(target, std::move(message));
    } catch (const std::length_error &e) {
        target.status = AnalysisStatus::Limited;
        target.error = e.what();
    }
}
std::array<ApplicationInput, 2> streamInputs(const TcpStreamRequest &request,
                                             const TcpStreamResult &stream) {
    std::map<std::uint64_t, const Packet *> packets;
    for (const auto &p : request.packets)
        packets[p->id] = p.get();
    std::array<ApplicationInput, 2> input;
    for (unsigned side = 0; side < 2; ++side) {
        auto bytes = std::make_shared<std::vector<std::uint8_t>>();
        auto &target = input[side];
        const auto &source = stream.directions[side];
        target.direction = side;
        target.source = DataSource::Reassembled;
        target.startKnown = source.startKnown && !source.prefixMissing;
        target.endKnown = request.end[side].has_value() && !source.suffixMissing;
        target.incomplete = source.limited || source.prefixMissing || source.suffixMissing ||
                            source.conflictBytes || stream.inputLimited;
        for (const auto &block : source.blocks) {
            if (block.bytes.empty()) {
                target.incomplete = true;
                break;
            }
            const auto found = packets.find(block.packetId);
            if (found == packets.end())
                break;
            const auto &packet = *found->second;
            const auto &tcp = *packet.tcp;
            const auto sequence = tcp.sequence + ((tcp.flags & 2) ? 1u : 0u);
            const auto offset = std::uint32_t(block.sequence - sequence);
            if (offset > tcp.payloadLength || block.bytes.size() > tcp.payloadLength - offset) {
                target.incomplete = true;
                break;
            }
            target.sources.push_back(
                {packet.id, tcp.payloadOffset + offset, block.bytes.size(), bytes->size()});
            bytes->insert(bytes->end(), block.bytes.begin(), block.bytes.end());
        }
        target.bytes = std::move(bytes);
    }
    return input;
}
bool begins(const ApplicationInput &input, std::string_view prefix) {
    return input.bytes && input.bytes->size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), input.bytes->begin());
}
} // namespace
ApplicationResult analyzeDatagram(const Packet &packet) {
    ApplicationResult result;
    if (!packet.udp || (packet.udp->sourcePort != 53 && packet.udp->destinationPort != 53))
        return result;
    const auto &udp = *packet.udp;
    if (!udp.completeDatagram ||
        !containsBytes(packet.raw.bytes.size(), udp.payloadOffset, udp.payloadLength)) {
        result.status = AnalysisStatus::Incomplete;
        return result;
    }
    ApplicationInput input;
    input.source = DataSource::Original;
    input.startKnown = input.endKnown = true;
    input.bytes = std::make_shared<const std::vector<std::uint8_t>>(packet.raw.bytes);
    input.sources = {{packet.id, 0, packet.raw.bytes.size(), 0}};
    result = decodeDns(input, udp.payloadOffset, udp.payloadLength);
    result.estimatedBytes = estimateApplicationBytes(result);
    return result;
}
ApplicationResult analyzeConversation(const TcpStreamRequest &request, const TlsKeyLog &keys,
                                      std::stop_token stop) {
    const auto stream = reassembleTcp(request, stop);
    auto input = streamInputs(request, stream);
    ApplicationResult result;
    if (stop.stop_requested())
        return result;
    if (request.key.a.port == 53 || request.key.b.port == 53) {
        for (const auto &side : input) {
            if (!side.bytes)
                continue;
            ByteView view(*side.bytes);
            std::size_t cursor = 0;
            if (!side.startKnown && !side.bytes->empty()) {
                result.status = AnalysisStatus::Incomplete;
                continue;
            }
            while (cursor < side.bytes->size()) {
                if (stop.stop_requested())
                    return result;
                if (!containsBytes(side.bytes->size(), cursor, 2)) {
                    result.status = AnalysisStatus::Incomplete;
                    break;
                }
                const auto length = static_cast<std::size_t>(view.integer(cursor, 2));
                cursor += 2;
                if (!length || !containsBytes(side.bytes->size(), cursor, length)) {
                    result.status = AnalysisStatus::Incomplete;
                    break;
                }
                merge(result, decodeDns(side, cursor, length));
                cursor += length;
            }
        }
    } else {
        bool tls = false;
        for (const auto &side : input)
            if (side.bytes && side.bytes->size() >= 3 && (*side.bytes)[0] >= 20 &&
                (*side.bytes)[0] <= 23 && (*side.bytes)[1] == 3)
                tls = true;
        if (tls) {
            auto decoded = decodeTls(input, keys, stop);
            result = std::move(decoded.analysis);
            if (decoded.decrypted) {
                auto application = decoded.alpn == "h2" ||
                                           begins(decoded.plaintext[0], "PRI * HTTP/2.0") ||
                                           begins(decoded.plaintext[1], "PRI * HTTP/2.0")
                                       ? decodeHttp2(decoded.plaintext, stop)
                                       : decodeHttp1(decoded.plaintext, stop);
                merge(result, std::move(application));
            }
        } else if (begins(input[0], "PRI * HTTP/2.0") || begins(input[1], "PRI * HTTP/2.0"))
            result = decodeHttp2(input, stop);
        else {
            bool http = request.key.a.port == 80 || request.key.b.port == 80 ||
                        request.key.a.port == 8080 || request.key.b.port == 8080;
            for (const auto &side : input)
                if (side.bytes && !side.bytes->empty()) {
                    const std::string_view bytes(
                        reinterpret_cast<const char *>(side.bytes->data()),
                        std::min<std::size_t>(side.bytes->size(), applicationHeaderLimit));
                    http |= bytes.starts_with("HTTP/1.") ||
                            bytes.find(" HTTP/1.") != std::string_view::npos;
                }
            if (http)
                result = decodeHttp1(input, stop);
        }
    }
    if (stream.inputLimited || stream.directions[0].limited || stream.directions[1].limited)
        result.status = AnalysisStatus::Limited;
    else if ((input[0].incomplete || input[1].incomplete) &&
             result.status == AnalysisStatus::Complete)
        result.status = AnalysisStatus::Incomplete;
    result.estimatedBytes = estimateApplicationBytes(result);
    if (result.estimatedBytes > applicationResultLimit) {
        result.messages = {};
        result.status = AnalysisStatus::Limited;
        result.error = "Application result limit reached";
        result.estimatedBytes = estimateApplicationBytes(result);
    }
    return result;
}
std::size_t estimateApplicationBytes(const ApplicationResult &result) {
    std::size_t bytes = sizeof(result) + result.error.capacity() +
                        result.messages.capacity() * sizeof(ApplicationMessage);
    std::set<const void *> buffers;
    for (const auto &m : result.messages) {
        bytes += m.protocol.capacity() + m.summary.capacity() +
                 m.sources.capacity() * sizeof(SourceSpan) +
                 m.fields.capacity() * sizeof(ApplicationField);
        if (m.bytes && buffers.insert(m.bytes.get()).second)
            bytes += sizeof(*m.bytes) + m.bytes->capacity();
        for (const auto &f : m.fields) {
            bytes += f.name.capacity() + f.key.capacity();
            if (const auto *s = std::get_if<std::string>(&f.value))
                bytes += s->capacity();
        }
    }
    return bytes;
}
std::size_t estimateApplicationFact(const ApplicationFacts &fact) {
    std::size_t bytes = sizeof(std::pair<const std::uint64_t, ApplicationFacts>) + 64;
    for (const auto &[name, values] : fact.values) {
        bytes += sizeof(decltype(fact.values)::value_type) + 64 + name.capacity() +
                 values.capacity() * sizeof(ApplicationValue);
        for (const auto &value : values)
            if (const auto *text = std::get_if<std::string>(&value))
                bytes += text->capacity();
    }
    return bytes;
}
std::size_t estimateApplicationFacts(const std::map<std::uint64_t, ApplicationFacts> &facts) {
    std::size_t bytes = 0;
    for (const auto &[id, fact] : facts) {
        (void)id;
        bytes += estimateApplicationFact(fact);
    }
    return bytes;
}
std::map<std::uint64_t, ApplicationFacts>
indexApplication(const ApplicationResult &result,
                 std::span<const std::shared_ptr<const Packet>> packets) {
    constexpr std::size_t budget = 1024 * 1024;
    std::map<std::uint64_t, ApplicationFacts> index;
    std::set<std::uint64_t> retained;
    std::set<std::uint64_t> limited;
    for (const auto &packet : packets)
        retained.insert(packet->id);
    std::size_t bytes = 0;
    // Publish message facts before allocating empty status records. Prefer recent output.
    for (auto message = result.messages.rbegin(); message != result.messages.rend(); ++message) {
        std::set<std::uint64_t> ids;
        for (const auto &span : message->sources)
            if (retained.contains(span.packetId))
                ids.insert(span.packetId);
        std::string protocol = message->protocol;
        for (auto &c : protocol)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (const auto id : ids) {
            const auto old = index.find(id);
            const auto previous = old == index.end() ? 0 : estimateApplicationFact(old->second);
            ApplicationFacts candidate = old == index.end() ? ApplicationFacts{} : old->second;
            candidate.status = limited.contains(id) ? AnalysisStatus::Limited : result.status;
            candidate.values[protocol] = {true};
            if (protocol == "tls") {
                static constexpr std::array<const char *, 7> names = {
                    "pending",      "complete",    "incomplete",           "limited",
                    "missing_keys", "unsupported", "authentication_failed"};
                candidate.values["tls.status"] = {
                    std::string(names[static_cast<std::size_t>(result.status)])};
            }
            for (const auto &field : message->fields)
                if (!field.key.empty()) {
                    auto &values = candidate.values[field.key];
                    if (std::find(values.begin(), values.end(), field.value) == values.end())
                        values.push_back(field.value);
                }
            const auto cost = estimateApplicationFact(candidate);
            if (cost <= budget && bytes - previous <= budget - cost) {
                bytes = bytes - previous + cost;
                index[id] = std::move(candidate);
            } else {
                limited.insert(id);
                if (old != index.end())
                    old->second.status = AnalysisStatus::Limited;
            }
        }
    }
    for (auto packet = packets.rbegin(); packet != packets.rend(); ++packet) {
        if (index.contains((*packet)->id))
            continue;
        ApplicationFacts fact;
        fact.status =
            limited.contains((*packet)->id)
                ? AnalysisStatus::Limited
                : (((*packet)->tcp && !(*packet)->tcp->payloadLength) ? AnalysisStatus::Complete
                                                                      : result.status);
        const auto cost = estimateApplicationFact(fact);
        if (cost > budget - bytes)
            break;
        bytes += cost;
        index.emplace((*packet)->id, std::move(fact));
    }
    return index;
}
} // namespace etherscope
