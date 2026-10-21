#include "core/application.h"
#include "core/application_stream.h"
#include "core/display_filter.h"
#include "core/tls.h"
#include "core/application_index.h"
#include <cstdlib>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *bytes, std::size_t size) {
    using namespace etherscope;
    if (!size || size > 65535)
        return 0;
    ApplicationInput input;
    input.bytes = std::make_shared<const std::vector<std::uint8_t>>(bytes + 1, bytes + size);
    input.sources = {{1, 0, size - 1, 0}};
    input.startKnown = input.endKnown = true;
    ApplicationResult result;
    switch (bytes[0] % 6) {
    case 0:
        result = decodeDns(input);
        break;
    case 1:
        result = decodeHttp1({input, {}});
        break;
    case 2:
        result = decodeHttp2({input, {}});
        break;
    case 3: {
        TlsKeyLog keys;
        result = decodeTls({input, {}}, keys).analysis;
        break;
    }
    case 5: {
        ApplicationIndex index;
        for (std::size_t cursor = 1; cursor + 2 < size && cursor < 1024; cursor += 3) {
            const auto id = std::uint64_t(bytes[cursor]) + 1;
            auto packet = std::make_shared<Packet>();
            packet->id = id;
            packet->tcp = TcpInfo{};
            packet->tcp->payloadLength = 1;
            index.observe({1, 256, 256, {packet}});
            ApplicationFacts facts;
            facts.status = static_cast<AnalysisStatus>(bytes[cursor + 1] % 7);
            facts.values["http.host"] = {std::string(1, static_cast<char>(bytes[cursor + 2]))};
            auto value = std::make_shared<ApplicationResult>();
            value->estimatedBytes = sizeof(ApplicationResult);
            if (bytes[cursor + 2] & 1)
                index.prune(id, 256);
            else
                index.apply(bytes[cursor + 2] % 16, std::move(value), {{id, std::move(facts)}});
            if (bytes[cursor + 2] & 4)
                index.limit(std::span(&id, 1));
            if (index.estimatedBytes() > applicationIndexBudget)
                std::abort();
        }
        std::array<std::size_t, 7> expected{};
        for (std::uint64_t id = 1; id <= 256; ++id)
            if (const auto *facts = index.facts(id))
                ++expected[static_cast<std::size_t>(facts->status)];
        if (expected != index.diagnostics().states)
            std::abort();
        index.clear();
        if (index.estimatedBytes())
            std::abort();
        return 0;
    }
    default: {
        const auto filter = compileDisplayFilter(
            std::string_view(reinterpret_cast<const char *>(bytes + 1), size - 1));
        if (filter.value) {
            Packet p;
            filter.value->evaluate(p);
        }
        return 0;
    }
    }
    if (bytes[0] % 6 >= 1 && bytes[0] % 6 <= 3) {
        Http1Stream http1;
        Http2Stream http2;
        TlsStream tls;
        TlsKeyLog keys;
        for (std::size_t cursor = 1; cursor < size;) {
            const auto count = std::min<std::size_t>(1 + bytes[cursor] % 127, size - cursor);
            ApplicationInput part;
            part.bytes = std::make_shared<const std::vector<std::uint8_t>>(bytes + cursor,
                                                                           bytes + cursor + count);
            part.sources = {{cursor, 0, count, 0}};
            part.startKnown = true;
            part.endKnown = cursor + count == size;
            result = bytes[0] % 6 == 1   ? http1.append({part, {}})
                     : bytes[0] % 6 == 2 ? http2.append({part, {}})
                                         : tls.append({part, {}}, keys).analysis;
            cursor += count;
        }
    }
    if (result.messages.size() > 4096)
        std::abort();
    for (const auto &m : result.messages) {
        if (!m.bytes || m.offset > m.bytes->size() || m.length > m.bytes->size() - m.offset ||
            m.fields.size() > maxPacketFields)
            std::abort();
        for (const auto &f : m.fields)
            if (f.offset > m.bytes->size() || f.length > m.bytes->size() - f.offset)
                std::abort();
    }
    return 0;
}
