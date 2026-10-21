#pragma once
#include "core/display_filter.h"
#include <deque>

namespace etherscope {
class ApplicationIndex {
  public:
    void clear();
    void apply(std::uint64_t conversation, std::shared_ptr<const ApplicationResult> result,
               std::map<std::uint64_t, ApplicationFacts> facts);
    void prune(std::uint64_t first, std::uint64_t last);
    const ApplicationFacts *facts(std::uint64_t packet) const;
    std::vector<std::shared_ptr<const ApplicationResult>> results(std::uint64_t packet) const;
    std::vector<std::shared_ptr<const ApplicationResult>> conversation(std::uint64_t id) const;
    std::size_t estimatedBytes() const {
        return bytes_ + facts_.size() * (sizeof(ApplicationFacts) + 64);
    }
    std::pair<std::size_t, std::size_t> unresolved() const;

  private:
    struct Entry {
        std::shared_ptr<const ApplicationResult> result;
        std::vector<std::uint64_t> packets;
        std::size_t bytes{};
    };
    std::map<std::pair<bool, std::uint64_t>, Entry> entries_;
    std::map<std::uint64_t, ApplicationFacts> facts_;
    std::deque<std::pair<bool, std::uint64_t>> order_;
    std::size_t bytes_{};
};
} // namespace etherscope
