#pragma once
#include <cstdint>

namespace etherscope {
// Numeric packet/conversation IDs are meaningful only within one source generation.
struct SourceContext {
    int session{-1};
    std::uint64_t generation{}, analysisGeneration{};
    bool operator==(const SourceContext &) const = default;
};
} // namespace etherscope
