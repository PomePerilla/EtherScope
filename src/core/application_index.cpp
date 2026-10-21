#include "core/application_index.h"
#include <algorithm>

namespace etherscope {
namespace {
constexpr std::size_t treeNodeOverhead = 64;
constexpr std::size_t membershipBytes = sizeof(std::uint64_t) + treeNodeOverhead;
} // namespace

std::size_t ApplicationIndex::estimateFactBytes(const ApplicationFacts &facts) {
    std::size_t bytes = sizeof(FactRecord) + treeNodeOverhead;
    for (const auto &[name, values] : facts.values) {
        bytes += sizeof(decltype(facts.values)::value_type) + treeNodeOverhead + name.capacity() +
                 values.capacity() * sizeof(ApplicationValue);
        for (const auto &value : values)
            if (const auto *text = std::get_if<std::string>(&value))
                bytes += text->capacity();
    }
    return bytes;
}
void ApplicationIndex::clear() {
    entries_.clear();
    facts_.clear();
    order_.clear();
    bytes_ = 0;
    nextEntry_ = 0;
}
const ApplicationFacts *ApplicationIndex::facts(std::uint64_t id) const {
    const auto found = facts_.find(id);
    return found == facts_.end() ? nullptr : &found->second.value;
}
void ApplicationIndex::eraseEmptyEntry(Entries::iterator entry) {
    bytes_ -= entry->second.bytes;
    order_.erase(entry->second.id);
    entries_.erase(entry);
}
void ApplicationIndex::detach(std::uint64_t packet, FactRecord &record) {
    if (!record.owner)
        return;
    const auto entry = entries_.find(record.key);
    if (entry != entries_.end() && entry->second.id == record.owner) {
        if (entry->second.packets.erase(packet))
            bytes_ -= membershipBytes;
        if (entry->second.packets.empty())
            eraseEmptyEntry(entry);
    }
    record.owner = 0;
    record.key = {};
}
void ApplicationIndex::removeEntry(Entries::iterator entry, bool retainLimited) {
    for (const auto packet : entry->second.packets) {
        const auto found = facts_.find(packet);
        if (found == facts_.end() || found->second.owner != entry->second.id)
            continue;
        bytes_ -= found->second.bytes;
        if (retainLimited) {
            auto &record = found->second;
            record.value = {};
            record.value.status = AnalysisStatus::Limited;
            record.owner = 0;
            record.key = {};
            record.bytes = estimateFactBytes(record.value);
            bytes_ += record.bytes;
        } else {
            facts_.erase(found);
        }
    }
    bytes_ -= entry->second.packets.size() * membershipBytes;
    eraseEmptyEntry(entry);
}
void ApplicationIndex::apply(std::uint64_t conversation,
                             std::shared_ptr<const ApplicationResult> result,
                             std::map<std::uint64_t, ApplicationFacts> facts) {
    if (facts.empty())
        return;
    const EntryKey key{conversation != 0, conversation ? conversation : facts.begin()->first};
    if (const auto old = entries_.find(key); old != entries_.end())
        removeEntry(old, false);

    Entry entry;
    entry.id = ++nextEntry_;
    entry.result = std::move(result);
    entry.bytes =
        sizeof(Entries::value_type) + treeNodeOverhead + sizeof(decltype(order_)::value_type) +
        treeNodeOverhead +
        (entry.result ? std::max(sizeof(ApplicationResult), entry.result->estimatedBytes) : 0);
    const auto current = entries_.emplace(key, std::move(entry)).first;
    order_.emplace(current->second.id, key);
    bytes_ += current->second.bytes;
    for (auto &[packet, value] : facts) {
        auto [found, inserted] = facts_.try_emplace(packet);
        auto &record = found->second;
        if (!inserted) {
            // An aggregate limit notification can overlap several connection entries.
            detach(packet, record);
            bytes_ -= record.bytes;
        }
        record.value = std::move(value);
        record.key = key;
        record.owner = current->second.id;
        record.bytes = estimateFactBytes(record.value);
        current->second.packets.insert(packet);
        bytes_ += record.bytes + membershipBytes;
    }
    while (bytes_ > applicationIndexBudget && !order_.empty())
        removeEntry(entries_.find(order_.begin()->second), true);
}
void ApplicationIndex::prune(std::uint64_t first, std::uint64_t last) {
    for (auto found = facts_.begin(); found != facts_.end();) {
        if (first && found->first >= first && found->first <= last) {
            ++found;
            continue;
        }
        detach(found->first, found->second);
        bytes_ -= found->second.bytes;
        found = facts_.erase(found);
    }
}
std::vector<std::shared_ptr<const ApplicationResult>>
ApplicationIndex::results(std::uint64_t packet) const {
    const auto found = facts_.find(packet);
    if (found == facts_.end() || !found->second.owner)
        return {};
    const auto entry = entries_.find(found->second.key);
    if (entry == entries_.end() || entry->second.id != found->second.owner || !entry->second.result)
        return {};
    return {entry->second.result};
}
std::vector<std::shared_ptr<const ApplicationResult>>
ApplicationIndex::conversation(std::uint64_t id) const {
    const auto found = entries_.find({true, id});
    if (found == entries_.end() || !found->second.result)
        return {};
    return {found->second.result};
}
std::pair<std::size_t, std::size_t> ApplicationIndex::unresolved() const {
    std::size_t pending = 0, incomplete = 0;
    for (const auto &[id, record] : facts_) {
        (void)id;
        if (record.value.status == AnalysisStatus::Pending)
            ++pending;
        else if (record.value.status != AnalysisStatus::Complete)
            ++incomplete;
    }
    return {pending, incomplete};
}
} // namespace etherscope
