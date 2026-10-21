#include "core/application_stream.h"
#include "core/application_analyzer.h"
#include "core/session.h"
#include "fixtures.h"
#include <iostream>
#include <stdexcept>

using namespace etherscope;
namespace {
unsigned checks{};
void check(bool condition, const char *message) {
    ++checks;
    if (!condition)
        throw std::runtime_error(message);
}
ApplicationInput chunk(std::string_view text, unsigned side, std::uint64_t packet,
                       bool end = false) {
    ApplicationInput input;
    input.bytes = std::make_shared<const std::vector<std::uint8_t>>(text.begin(), text.end());
    input.sources = {{packet, 54, text.size(), 0}};
    input.direction = side;
    input.startKnown = true;
    input.endKnown = end;
    return input;
}
std::vector<std::pair<std::string, ApplicationValue>> fields(const ApplicationResult &result) {
    std::vector<std::pair<std::string, ApplicationValue>> values;
    for (const auto &message : result.messages)
        for (const auto &field : message.fields)
            values.emplace_back(field.key, field.value);
    return values;
}
void http1() {
    const std::string request =
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHEAD /x HTTP/1.1\r\n\r\n";
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 200 "
                                 "OK\r\nContent-Length: 100\r\n\r\n";
    const auto expected = decodeHttp1({chunk(request, 0, 1), chunk(response, 1, 2)});
    Http1Stream stream;
    ApplicationResult result;
    std::uint64_t packet = 1;
    for (const auto &text : {request, response}) {
        const auto side = text == request ? 0u : 1u;
        for (const auto byte : text) {
            std::array<ApplicationInput, 2> input;
            input[side] = chunk(std::string_view(&byte, 1), side, packet++);
            result = stream.append(input);
        }
    }
    check(result.status == AnalysisStatus::Complete && result.messages.size() == 4,
          "HTTP/1 one-byte input completes four messages");
    check(fields(result) == fields(expected), "HTTP/1 incremental fields equal whole-input fields");
    const auto snapshot = result;
    const auto old = *snapshot.messages.front().bytes;
    std::array<ApplicationInput, 2> next;
    next[0] = chunk("GET /next HTTP/1.1\r\n\r\n", 0, packet++);
    result = stream.append(next);
    check(*snapshot.messages.front().bytes == old && result.messages.size() == 5,
          "Published messages remain immutable when another message arrives");
    stream.prune(packet);
    check(stream.append({}).messages.empty(), "Incremental HTTP messages release after pruning");

    const std::string chunked = "POST / HTTP/1.1\r\nTransfer-Encoding: "
                                "chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-Test: yes\r\n\r\n";
    Http1Stream chunks;
    for (std::size_t at = 0; at < chunked.size(); ++at) {
        next = {};
        next[0] = chunk(std::string_view(chunked).substr(at, 1), 0, at + 1);
        result = chunks.append(next);
        if (at + 1 < chunked.size() && at > chunked.find("\r\n\r\n"))
            check(result.status == AnalysisStatus::Incomplete,
                  "Chunked body stays incomplete until trailers finish");
    }
    check(result.status == AnalysisStatus::Complete && result.messages.size() == 1,
          "Incremental chunk scanner completes at the trailer terminator");
    Http1Stream close;
    next = {};
    next[0] = chunk("GET / HTTP/1.1\r\n\r\n", 0, 1);
    close.append(next);
    next = {};
    next[1] = chunk("HTTP/1.0 200 OK\r\n\r\nabc", 1, 2);
    check(close.append(next).status == AnalysisStatus::Incomplete,
          "Close-delimited response awaits FIN");
    next = {};
    next[1] = chunk({}, 1, 3, true);
    result = close.append(next);
    check(result.status == AnalysisStatus::Complete && result.messages.size() == 2,
          "Close-delimited response completes on an empty end update");
    Http1Stream lateRequest;
    next = {};
    next[1] = chunk("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 1, 2);
    check(lateRequest.append(next).status == AnalysisStatus::Incomplete,
          "Response arriving before its request does not guess body framing");
    next = {};
    next[0] = chunk("HEAD / HTTP/1.1\r\n\r\n", 0, 1);
    result = lateRequest.append(next);
    check(result.status == AnalysisStatus::Complete && result.messages.size() == 2,
          "Late HEAD request resolves response framing without replay");
}
void http2() {
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    auto frame = [](unsigned type, unsigned flags, unsigned stream, std::string bytes) {
        const auto length = bytes.size();
        std::string header(9, '\0');
        for (unsigned index = 0; index < 3; ++index)
            header[index] = static_cast<char>(length >> ((2 - index) * 8));
        header[3] = static_cast<char>(type);
        header[4] = static_cast<char>(flags);
        for (unsigned index = 0; index < 4; ++index)
            header[5 + index] = static_cast<char>(stream >> ((3 - index) * 8));
        return header + bytes;
    };
    const std::string headers = std::string("\x82\x86\x84\x41\x0f", 5) + "www.example.com";
    const auto request = preface + frame(4, 0, 0, {}) + frame(1, 1, 1, headers.substr(0, 4)) +
                         frame(9, 4, 1, headers.substr(4)) +
                         frame(1, 5, 3, std::string("\x82\x86\x84\xbe", 4));
    const auto response = frame(4, 0, 0, {}) + frame(1, 5, 1, std::string("\x88", 1));
    const auto expected = decodeHttp2({chunk(request, 0, 1), chunk(response, 1, 2)});
    check(expected.status == AnalysisStatus::Complete, "Whole-input HTTP/2 fixture is valid");
    Http2Stream stream;
    ApplicationResult result;
    std::uint64_t packet = 1;
    for (const auto &text : {request, response}) {
        const auto side = text == request ? 0u : 1u;
        for (const auto byte : text) {
            std::array<ApplicationInput, 2> input;
            input[side] = chunk(std::string_view(&byte, 1), side, packet++);
            result = stream.append(input);
        }
    }
    if (result.status != AnalysisStatus::Complete)
        throw std::runtime_error("Incremental HTTP/2: " + result.error);
    check(fields(result) == fields(expected),
          "HTTP/2 incremental CONTINUATION and dynamic HPACK equal whole-input fields");
    const auto before = result;
    const auto original = *before.messages.front().bytes;
    std::array<ApplicationInput, 2> next;
    next[0] = chunk(frame(0, 1, 3, "body"), 0, packet++);
    result = stream.append(next);
    check(*before.messages.front().bytes == original &&
              result.messages.size() == before.messages.size() + 1,
          "HTTP/2 snapshots remain immutable after new frames");
    stream.prune(packet);
    check(stream.append({}).messages.empty(),
          "HTTP/2 pruning releases completed messages without resetting HPACK");
    next[0] = chunk(frame(1, 5, 5, std::string("\x82\x86\x84\xbe", 4)), 0, packet++);
    result = stream.append(next);
    check(result.status == AnalysisStatus::Complete && result.messages.size() == 1,
          "HPACK dynamic state survives pruning of all previous messages");
}
void conversations() {
    SessionStore store;
    const std::string request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    for (auto raw :
         {fixtures::tcp(2, 99), fixtures::tcp(18, 499, 100, true), fixtures::tcp(16, 100, 500)})
        store.append(decodeSummary(std::move(raw)));
    // Observe the suffix first. Only a later gap fill can release contiguous bytes.
    store.append(decodeSummary(
        fixtures::tcp(24, 110, 500, false, 50000, false, {request.begin() + 10, request.end()})));
    store.append(decodeSummary(
        fixtures::tcp(24, 100, 500, false, 50000, false, {request.begin(), request.begin() + 10})));
    store.append(decodeSummary(
        fixtures::tcp(24, 100, 500, false, 50000, false, {request.begin(), request.end()})));
    const auto id = store.tcp().items().front().id;
    auto whole = *snapshotTcpStream(store, id);
    const TlsKeyLog keys;
    const auto expected = analyzeConversation(whole, keys);
    ConversationAnalysis stream;
    ApplicationResult result;
    for (std::size_t index = 0; index < whole.packets.size(); ++index) {
        auto part = whole;
        part.packets = {whole.packets[index]};
        result = stream.append(part, keys);
        if (index == 3)
            check(result.messages.empty() && result.status != AnalysisStatus::Complete,
                  "TCP gap defers parsing instead of treating suffix bytes as a new message");
    }
    check(result.status == expected.status && fields(result) == fields(expected),
          "Incremental TCP gap fill and retransmission equal whole-stream analysis");
    check(stream.deliveredBytes() == request.size(), "Retransmissions do not redeliver bytes");
    auto repeat = whole;
    result = stream.append(repeat, keys);
    check(result.messages.size() == 1 && stream.deliveredBytes() == request.size(),
          "Already submitted packet objects are ignored");
    const auto previous = result;
    stream.prune(100);
    repeat.packets.clear();
    check(stream.append(repeat, keys).messages.empty(),
          "Cache eviction prunes messages without resetting stream state");
    check(previous.messages.size() == 1 && !previous.messages[0].bytes->empty(),
          "Caller snapshots survive parser pruning");

    // Keep one live connection beyond both the packet cache and a direction's byte budget.
    const auto packetTemplate = *whole.packets.back();
    ConversationAnalysis sustained;
    auto metadata = whole;
    metadata.packets.clear();
    metadata.start[0] = 0xfffffff0u;
    metadata.start[1] = 500;
    std::uint64_t total = 0, responseTotal = 0;
    for (unsigned round = 0; round < 24000; ++round) {
        auto packet = std::make_shared<Packet>(packetTemplate);
        const std::string message = "GET /keep HTTP/1.1\r\nHost: persistent.example\r\n\r\n";
        *packet =
            decodeSummary(fixtures::tcp(24, 0xfffffff0u + static_cast<std::uint32_t>(total), 500,
                                        false, 50000, false, {message.begin(), message.end()}));
        packet->id = round * 2 + 1;
        packet->tcpConversationId = metadata.conversationId;
        const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        auto reply = std::make_shared<Packet>(
            decodeSummary(fixtures::tcp(24, 500 + static_cast<std::uint32_t>(responseTotal), 0,
                                        true, 50000, false, {response.begin(), response.end()})));
        reply->id = packet->id + 1;
        reply->tcpConversationId = metadata.conversationId;
        metadata.packets = {packet, reply};
        sustained.prune(packet->id);
        result = sustained.append(metadata, keys);
        if (result.status != AnalysisStatus::Complete || result.messages.size() != 2)
            throw std::runtime_error("Sustained incremental stream: " + std::to_string(round) +
                                     " " + result.error);
        total += message.size();
        responseTotal += response.size();
    }
    check(total > streamDirectionLimit && sustained.deliveredBytes() == total + responseTotal,
          "Long-lived connection advances across sequence wrap without a lifetime byte limit");
    check(sustained.estimatedBytes() < 512 * 1024,
          "Consumed history and pruned messages remain bounded");
}
void boundedMessageWindow() {
    Http1Stream stream;
    ApplicationResult result;
    for (unsigned round = 0; round < 1300; ++round) {
        result = stream.append(
            {chunk("GET / HTTP/1.1\r\nHost: window.example\r\n\r\n", 0, 2 * round + 1),
             chunk("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 1, 2 * round + 2)});
    }
    check(result.status == AnalysisStatus::Limited && result.messages.size() <= 1024,
          "Message window evicts old output without stopping a live parser");
    stream.prune(2601);
    result = stream.append({chunk("GET /later HTTP/1.1\r\nHost: later.example\r\n\r\n", 0, 2601),
                            chunk("HTTP/1.1 204 Empty\r\n\r\n", 1, 2602)});
    check(result.status == AnalysisStatus::Complete && result.messages.size() == 2,
          "Advancing the cache floor restores complete status after output eviction");
}
} // namespace
int main() {
    try {
        http1();
        http2();
        conversations();
        boundedMessageWindow();
        std::cout << checks << " incremental application checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
