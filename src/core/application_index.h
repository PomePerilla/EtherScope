#pragma once
#include "core/display_filter.h"
#include "core/session.h"
#include <set>

namespace etherscope {
struct IndexDelta {
    std::set<std::uint64_t> packets;
};
struct AnalysisDiagnostics {
    std::array<std::size_t, 7> states{};
    std::size_t eligible{};
    std::uint64_t evictedEntries{}, evictedPackets{};
    std::size_t count(AnalysisStatus status) const {
        return states[static_cast<std::size_t>(status)];
    }
    std::size_t incomplete() const {
        return eligible - count(AnalysisStatus::Pending) - count(AnalysisStatus::Complete);
    }
};
class ApplicationIndex {
  public:
    void clear();
    void apply(std::uint64_t conversation, std::shared_ptr<const ApplicationResult> result,
               std::map<std::uint64_t, ApplicationFacts> facts, IndexDelta *delta = nullptr,
               std::pair<std::uint64_t, std::uint64_t> revision = {});
    void prune(std::uint64_t first, std::uint64_t last, IndexDelta *delta = nullptr);
    void observe(const SessionDelta &delta, IndexDelta *changes = nullptr);
    AnalysisDiagnostics diagnostics() const {
        return diagnostics_;
    }
    const ApplicationFacts *facts(std::uint64_t packet) const;
    std::vector<std::shared_ptr<const ApplicationResult>> results(std::uint64_t packet) const;
    std::vector<std::shared_ptr<const ApplicationResult>> conversation(std::uint64_t id) const;
    std::size_t estimatedBytes() const {
        return bytes_;
    }
    std::pair<std::size_t, std::size_t> unresolved() const;

  private:
    using EntryKey = std::pair<bool, std::uint64_t>;
    struct FactRecord {
        ApplicationFacts value;
        EntryKey key{};
        std::uint64_t owner{};
        std::size_t bytes{};
    };
    struct Entry {
        std::uint64_t id{};
        std::pair<std::uint64_t, std::uint64_t> revision{};
        std::shared_ptr<const ApplicationResult> result;
        std::set<std::uint64_t> packets;
        // Fixed entry, ordering and result storage; memberships are charged separately.
        std::size_t bytes{};
    };
    using Entries = std::map<EntryKey, Entry>;
    Entries entries_;
    std::map<std::uint64_t, FactRecord> facts_;
    std::map<std::uint64_t, EntryKey> order_;
    std::size_t bytes_{};
    std::uint64_t nextEntry_{};
    std::map<std::uint64_t, AnalysisStatus> tracked_;
    AnalysisDiagnostics diagnostics_;
    IndexDelta *changes_{};
    void changed(std::uint64_t packet);
    void enforceBudget();
    static std::size_t estimateFactBytes(const ApplicationFacts &facts);
    void detach(std::uint64_t packet, FactRecord &record);
    void eraseEmptyEntry(Entries::iterator entry);
    void removeEntry(Entries::iterator entry, bool retainLimited);
};
} // namespace etherscope
