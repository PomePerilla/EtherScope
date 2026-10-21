#include "parser_invariants.h"
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    if (size < 5 || size > 65540)
        return 0;
    etherscope::RawPacket raw;
    raw.linkType = data[0] % 3 == 2 ? 0 : (data[0] % 3 == 1 ? 1 : 113);
    raw.originalLength = std::uint32_t(data[1]) | (std::uint32_t(data[2]) << 8) |
                         (std::uint32_t(data[3]) << 16) | (std::uint32_t(data[4]) << 24);
    raw.bytes.assign(data + 5, data + size);
    auto full = etherscope::decodePacket(raw), summary = etherscope::decodeSummary(raw);
    auto details = etherscope::decodeDetails(raw);
    std::size_t count = 0;
    if (summary.tcp && (summary.tcp->payloadOffset > raw.bytes.size() ||
                        summary.tcp->payloadLength > raw.bytes.size() - summary.tcp->payloadOffset))
        std::abort();
    if (!summary.fields.empty() || summary.fields.capacity() != 0 ||
        !etherscope::testing::sameSummary(full, summary) || full.fields != details.fields ||
        !etherscope::testing::validFields(details.fields, raw.bytes.size(), count))
        std::abort();
    return 0;
}
