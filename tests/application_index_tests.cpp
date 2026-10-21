#include "core/application_index.h"
#include "core/application_analyzer.h"
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
ApplicationFacts complete(std::string host = "example.com") {
    ApplicationFacts facts;
    facts.status = AnalysisStatus::Complete;
    facts.values["http.host"] = {std::move(host)};
    return facts;
}
ApplicationFacts limited() {
    ApplicationFacts facts;
    facts.status = AnalysisStatus::Limited;
    return facts;
}
std::shared_ptr<ApplicationResult> result(AnalysisStatus status = AnalysisStatus::Complete) {
    auto value = std::make_shared<ApplicationResult>();
    value->status = status;
    value->estimatedBytes = estimateApplicationBytes(*value);
    return value;
}
void overlapAndEviction() {
    ApplicationIndex index;
    auto first = result();
    std::weak_ptr<const ApplicationResult> firstReference = first;
    index.apply(42, std::move(first), {{1, complete()}, {2, complete()}});
    auto rejected = result(AnalysisStatus::Limited);
    std::weak_ptr<const ApplicationResult> rejectedReference = rejected;
    std::map<std::uint64_t, ApplicationFacts> batch;
    for (unsigned id = 1; id <= 1000; ++id)
        batch[id] = limited();
    index.apply(0, std::move(rejected), std::move(batch));
    check(firstReference.expired(), "Fully superseded connection releases its result");
    check(index.conversation(42).empty(), "Superseded connection is not queryable");

    auto fresh = result();
    index.apply(42, fresh, {{1, complete()}, {2, complete()}});
    check(index.results(1).size() == 1 && index.results(1).front() == fresh,
          "Packet queries return only the current owner");
    auto pressure = result();
    pressure->estimatedBytes = applicationIndexBudget - index.estimatedBytes();
    index.apply(43, std::move(pressure), {{1001, complete()}});
    check(rejectedReference.expired(), "Old aggregate is released under budget pressure");
    check(index.conversation(42).size() == 1, "Fresh connection survives old aggregate eviction");
    check(index.facts(1) && index.facts(1)->status == AnalysisStatus::Complete &&
              index.facts(1)->values.contains("http.host"),
          "Eviction cannot clear fields owned by a newer entry");
    check(index.estimatedBytes() <= applicationIndexBudget, "Index remains within its budget");

    auto packet = decodeSummary(fixtures::tcp(24, 100));
    packet.id = 1;
    packet.tcp->payloadLength = 1;
    const auto expression = compileDisplayFilter("http.host == \"example.com\"").value;
    check(expression->evaluate(packet, index.facts(1)) == FilterTruth::True,
          "Current application filter still matches after eviction");
    const auto negative = compileDisplayFilter("not http.host contains \"example\"").value;
    check(index.facts(3) && index.facts(3)->status == AnalysisStatus::Limited &&
              index.results(3).empty(),
          "Evicted facts keep a limited marker without an owning result");
    check(negative->evaluate(packet, index.facts(3)) == FilterTruth::Unknown,
          "Limited facts preserve three-valued filtering");
}
void replacementAndPruning() {
    ApplicationIndex index;
    auto aggregate = result(AnalysisStatus::Limited);
    std::weak_ptr<const ApplicationResult> aggregateReference = aggregate;
    index.apply(0, std::move(aggregate), {{1, limited()}, {2, limited()}, {3, limited()}});
    auto connection = result();
    std::weak_ptr<const ApplicationResult> connectionReference = connection;
    index.apply(7, std::move(connection), {{2, complete()}, {3, complete()}});
    index.apply(0, result(AnalysisStatus::Limited), {{1, limited()}});
    check(aggregateReference.expired(), "Replacing an aggregate releases the old result");
    check(index.facts(2)->status == AnalysisStatus::Complete && index.results(2).size() == 1,
          "Replacing an old key cannot erase another owner's facts");
    const auto before = index.estimatedBytes();
    index.prune(2, 2);
    check(!index.facts(1) && !index.facts(3) && index.facts(2),
          "Prune removes only out-of-range facts");
    check(index.estimatedBytes() < before && !connectionReference.expired(),
          "Partial prune releases accounting while retaining the current result");
    check(index.results(1).empty() && index.results(3).empty(), "Pruned packets have no results");
    index.prune(4, 4);
    check(connectionReference.expired() && index.estimatedBytes() == 0,
          "Final prune releases the result and all index accounting");
    index.prune(0, 0);
    check(index.estimatedBytes() == 0, "Empty prune is idempotent");
}
void namespacesAndAccounting() {
    ApplicationIndex index;
    auto tcp = result();
    auto udp = result();
    index.apply(7, tcp, {{70, complete()}});
    index.apply(0, udp, {{7, complete("dns.example")}});
    check(index.conversation(7).front() == tcp && index.results(7).front() == udp,
          "TCP conversation and datagram packet identifiers use separate namespaces");
    index.apply(7, result(), {{71, complete(std::string(4096, 'x'))}});
    check(!index.facts(70) && index.results(70).empty(),
          "Same-key replacement removes old members");
    const auto large = index.estimatedBytes();
    index.apply(7, result(), {{71, complete()}});
    const auto stable = index.estimatedBytes();
    check(stable < large, "Replacing long fields releases their dynamic storage charge");
    for (unsigned update = 0; update < 100; ++update) {
        index.apply(7, result(), {{71, complete()}});
        check(index.estimatedBytes() == stable,
              "Repeated replacement does not accumulate accounting");
        check(index.results(71).size() == 1, "Repeated replacement keeps one current result");
    }
    index.apply(7, result(), {});
    check(index.estimatedBytes() == stable, "Empty updates preserve the current entry");
    check(index.unresolved() == std::pair<std::size_t, std::size_t>{0, 0},
          "Complete entries have no unresolved markers");
    index.clear();
    check(index.estimatedBytes() == 0 && !index.facts(7) && index.results(71).empty() &&
              index.conversation(7).empty(),
          "Clear releases all lookup and accounting state");
}
void crossingConnections() {
    ApplicationIndex index;
    auto old = result();
    std::weak_ptr<const ApplicationResult> oldReference = old;
    index.apply(8, std::move(old), {{3, complete("old.example")}, {4, complete("old.example")}});
    auto current = result();
    index.apply(9, current, {{4, complete("current.example")}, {5, complete("current.example")}});
    index.apply(8, result(), {{3, complete("new.example")}, {6, complete("new.example")}});
    check(oldReference.expired(), "Replacing a partly superseded connection releases its result");
    check(index.results(4).size() == 1 && index.results(4).front() == current &&
              std::get<std::string>(index.facts(4)->values.at("http.host").front()) ==
                  "current.example",
          "Connection replacement preserves a different owner's shared packet");
    index.prune(4, 6);
    check(!index.facts(3) && index.conversation(8).size() == 1 && index.results(6).size() == 1,
          "Partial prune keeps the remaining membership of each connection");
    index.clear();
    check(index.estimatedBytes() == 0, "Crossing updates leave no residual accounting");
}
} // namespace
int main() {
    try {
        overlapAndEviction();
        replacementAndPruning();
        namespacesAndAccounting();
        crossingConnections();
        std::cout << checks << " application index checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
