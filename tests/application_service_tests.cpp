#include "capture/application_service.h"
#include "core/application_index.h"
#include "core/session.h"
#include "fixtures.h"
#include <QFile>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <atomic>

using namespace etherscope;
namespace {
void traffic(SessionStore &store) {
    const std::string request = "GET /index HTTP/1.1\r\nHost: example.com\r\n\r\n";
    for (auto raw :
         {fixtures::tcp(2, 99), fixtures::tcp(18, 499, 100, true), fixtures::tcp(16, 100, 500),
          fixtures::tcp(24, 100, 500, false, 50000, false, {request.begin(), request.end()})})
        store.append(decodeSummary(std::move(raw)));
}
std::vector<TcpConversation> connections(const SessionStore &store) {
    return {store.tcp().items().begin(), store.tcp().items().end()};
}
void applyUpdate(ApplicationIndex &index, ApplicationUpdate update) {
    if (update.limitedOnly) {
        for (const auto &[id, fact] : update.facts) {
            (void)fact;
            index.limit(std::span(&id, 1));
        }
    } else {
        index.apply(update.conversation, std::move(update.result), std::move(update.facts));
        index.limit(update.limitedPackets);
    }
}
} // namespace
class ApplicationServiceTests : public QObject {
    Q_OBJECT
  private slots:
    void oversizedDeliveryKeepsRecentMessagesAndFacts() {
        SessionStore store;
        for (unsigned i = 0; i < 2000; ++i)
            store.append(decodeSummary(fixtures::tcp(24, 100 + i, 0, false, 50000, false, {'x'})));
        ApplicationHooks hooks;
        auto expected = std::make_shared<std::map<std::uint64_t, ApplicationFacts>>();
        hooks.conversation = [expected](const TcpStreamRequest &request, const TlsKeyLog &, std::stop_token) {
            ApplicationResult result;
            std::array<std::shared_ptr<std::vector<std::uint8_t>>, 2> bytes;
            for (unsigned side = 0; side < 2; ++side) {
                bytes[side] = std::make_shared<std::vector<std::uint8_t>>();
                ApplicationMessage message;
                message.protocol = side == 0 ? "TLS" : "HTTP"; message.streamOffset = side * 1000000;
                message.bytes = bytes[side]; message.sources.reserve(1000);
                message.fields.push_back({side == 0 ? "SNI" : "Host", side == 0 ? "tls.sni" : "http.host", std::string(800, char('a' + side)), 0, 1});
                for (std::size_t n = side * 1000; n < (side + 1) * 1000 && n < request.packets.size(); ++n)
                    message.sources.push_back({request.packets[n]->id, 0, 1, 0});
                result.messages.push_back(std::move(message));
            }
            const auto size = (applicationResultLimit - estimateApplicationBytes(result) - 256) / 2;
            for (unsigned side = 0; side < 2; ++side) { bytes[side]->resize(size, std::uint8_t(side + 1)); result.messages[side].length = size; }
            result.estimatedBytes = estimateApplicationBytes(result);
            *expected = indexApplication(result, request.packets);
            return result;
        };
        ApplicationAnalysisService service(nullptr, hooks);
        service.submit({store.packets().begin(), store.packets().end()}, connections(store));
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        const auto stats = service.stats();
        QCOMPARE(stats.compactedUpdates, 1ULL); QCOMPARE(stats.stagingLimitedRecords, 0ULL);
        QVERIFY(stats.peakStagedBytes <= applicationStagingBudget);
        auto updates = service.takeResults(); QCOMPARE(updates.size(), 1u);
        const auto &update = updates.front(); QVERIFY(!update.limitedOnly);
        QCOMPARE(update.result->messages.size(), 1u);
        QCOMPARE(update.result->messages.front().streamOffset.value(), 1000000ULL);
        QCOMPARE(update.result->messages.front().bytes->front(), std::uint8_t(2));
        QCOMPARE(update.result->messages.front().bytes->size(), update.result->messages.front().length);
        QVERIFY(!update.facts.empty());
        QVERIFY(update.result->estimatedBytes <= applicationResultLimit);
        QCOMPARE(update.result->status, AnalysisStatus::Limited);
        QCOMPARE(update.facts.size(), expected->size());
        for (const auto &[id, fact] : *expected) {
            QCOMPARE(update.facts.at(id).status, fact.status);
            QVERIFY(update.facts.at(id).values == fact.values);
        }
        QVERIFY(update.keySensitive);
        service.reloadKeyLog();
        QVERIFY(!service.accepts(update));
    }
    void largeSnapshotsCoalesceWithinStagingBudget() {
        SessionStore store;
        for (unsigned i = 0; i < 2000; ++i)
            store.append(decodeSummary(fixtures::tcp(24, 100 + i, 0, false, 50000, false, {'x'})));
        ApplicationHooks hooks;
        hooks.conversation = [](const TcpStreamRequest &request, const TlsKeyLog &,
                                std::stop_token) {
            ApplicationResult result;
            result.estimatedBytes = applicationResultLimit;
            ApplicationMessage message;
            message.protocol = "HTTP";
            message.sources = {{request.packets.back()->id, 0, 1, 0}};
            message.fields.push_back({"Host", "http.host", std::string("latest.example"), 0, 1});
            result.messages.push_back(std::move(message));
            return result;
        };
        ApplicationAnalysisService service(nullptr, hooks);
        service.submit({store.packets().begin(), store.packets().end()}, connections(store));
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        QCOMPARE(service.stats().pendingUpdates, 1u);
        store.append(decodeSummary(fixtures::tcp(24, 2100, 0, false, 50000, false, {'x'})));
        service.submit({store.packets().back()}, connections(store));
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        const auto stats = service.stats();
        QCOMPARE(stats.pendingUpdates, 1u);
        QVERIFY(stats.coalescedUpdates >= 1);
        QCOMPARE(stats.stagingLimitedRecords, 0ULL);
        QVERIFY(stats.peakStagedBytes <= applicationStagingBudget);
        auto updates = service.takeResults();
        QCOMPARE(updates.size(), 1u);
        QVERIFY(!updates[0].limitedOnly);
        QVERIFY(updates[0].facts.at(store.packets().back()->id).values.contains("http.host"));
        QCOMPARE(service.stats().stagedBytes, 0u);
    }
    void keyCommandsAndGenerationsRejectOldResults() {
        ApplicationAnalysisService service;
        ApplicationUpdate old;
        old.generation = service.generation();
        QVERIFY(service.accepts(old));
        service.reloadKeyLog();
        QVERIFY(service.accepts(old));
        old.keySensitive = true;
        QVERIFY(!service.accepts(old));
        old.keyCommand = 1;
        QVERIFY(service.accepts(old));
        service.reset();
        QVERIFY(!service.accepts(old));
    }
    void incrementalStateSurvivesCacheEviction() {
        SessionStore store;
        traffic(store);
        auto info = store.tcp().items().front();
        std::weak_ptr<const Packet> first = store.packets().front();
        const auto originalBytes = store.packets().back()->tcp->payloadLength;
        ApplicationAnalysisService service;
        service.submit({store.packets().begin(), store.packets().end()}, connections(store), 1);
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        service.takeResults();
        QCOMPARE(service.stats().deliveredBytes, std::uint64_t(originalBytes));
        const std::string next = "GET /next HTTP/1.1\r\nHost: next.example\r\n\r\n";
        auto packet = std::make_shared<Packet>(decodeSummary(fixtures::tcp(
            24, 100 + originalBytes, 500, false, 50000, false, {next.begin(), next.end()})));
        packet->id = 5;
        packet->tcpConversationId = info.id;
        store.clear();
        service.submit({packet}, {info}, 5);
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy() && first.expired(), 5000);
        auto results = service.takeResults();
        QVERIFY(!results.empty());
        const auto &result = *results.back().result;
        QCOMPARE(result.status, AnalysisStatus::Complete);
        QCOMPARE(result.messages.size(), 1u);
        QCOMPARE(service.stats().deliveredBytes, std::uint64_t(originalBytes + next.size()));
        QVERIFY(service.stats().stateBytes <= applicationStateBudget &&
                service.stats().retainedBytes <= applicationInputBudget);
        QVERIFY(!results.back().facts.contains(4));
        const auto expression = compileDisplayFilter("http.host == \"next.example\"").value;
        QCOMPARE(expression->evaluate(*packet, &results.back().facts.at(5)), FilterTruth::True);

        QTemporaryDir directory;
        QFile file(directory.filePath("unrelated.keys"));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write(
            ("CLIENT_RANDOM " + std::string(64, '0') + " " + std::string(96, '0') + "\n").c_str());
        file.close();
        QSignalSpy keys(&service, &ApplicationAnalysisService::keyLogChanged);
        service.setKeyLog(file.fileName());
        QTRY_VERIFY_WITH_TIMEOUT(!keys.empty() && !service.busy(), 5000);
        QCOMPARE(service.stats().keyReplays, 0u);
        QCOMPARE(service.stats().deliveredBytes, std::uint64_t(originalBytes + next.size()));
    }
    void completedReplaySupersedesUndeliveredLimitMarker() {
        SessionStore store;
        traffic(store);
        ApplicationAnalysisService service;
        auto rejected = std::make_shared<Packet>();
        rejected->id = 4;
        rejected->estimatedBytes = applicationQueueBudget + 1;
        service.submit({rejected}, {});
        service.submit({store.packets().begin(), store.packets().end()}, connections(store));
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        ApplicationIndex index;
        for (auto &update : service.takeResults())
            applyUpdate(index, std::move(update));
        QVERIFY(index.facts(4));
        QCOMPARE(index.facts(4)->status, AnalysisStatus::Complete);
        const auto expression = compileDisplayFilter("http.host == \"example.com\"").value;
        QCOMPARE(expression->evaluate(*store.packets().back(), index.facts(4)), FilterTruth::True);
        QCOMPARE(index.results(4).size(), 1u);
    }
    void limitedNotificationKeepsFieldsAndSuccess() {
        SessionStore store;
        traffic(store);
        ApplicationAnalysisService service;
        ApplicationIndex index;
        auto collect = [&] {
            for (auto &update : service.takeResults()) {
                QCOMPARE(update.generation, service.generation());
                applyUpdate(index, std::move(update));
            }
        };
        auto submit = [&] {
            service.submit({store.packets().begin(), store.packets().end()}, connections(store));
        };
        submit();
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        collect();
        const auto expression = compileDisplayFilter("http.host == \"example.com\"").value;
        QCOMPARE(expression->evaluate(*store.packets().back(), index.facts(4)), FilterTruth::True);

        std::vector<std::shared_ptr<const Packet>> rejected;
        for (unsigned id = 1; id <= 1000; ++id) {
            auto packet = std::make_shared<Packet>();
            packet->id = id;
            packet->estimatedBytes = applicationQueueBudget + 1;
            rejected.push_back(std::move(packet));
        }
        service.submit(std::move(rejected), {});
        collect();
        QCOMPARE(index.facts(4)->status, AnalysisStatus::Limited);
        QCOMPARE(expression->evaluate(*store.packets().back(), index.facts(4)), FilterTruth::True);

        submit();
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        collect();
        QCOMPARE(index.results(4).size(), 1u);
        QCOMPARE(index.facts(4)->status, AnalysisStatus::Complete);
        QCOMPARE(expression->evaluate(*store.packets().back(), index.facts(4)), FilterTruth::True);
        QCOMPARE(index.results(4).size(), 1u);
        QVERIFY(index.estimatedBytes() <= applicationIndexBudget);
        index.prune(4, 4);
        QVERIFY(!index.facts(3));
        QCOMPARE(expression->evaluate(*store.packets().back(), index.facts(4)), FilterTruth::True);
    }
    void rejectedBatchStillReleasesEvictedPackets() {
        ApplicationAnalysisService service;
        SessionStore store;
        traffic(store);
        std::weak_ptr<const Packet> first = store.packets().front();
        service.submit({store.packets().begin(), store.packets().end()}, connections(store), 1);
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        store.clear();
        QVERIFY(!first.expired());
        auto large = std::make_shared<Packet>(decodeSummary(fixtures::icmp()));
        large->id = 5;
        large->estimatedBytes = applicationQueueBudget + 1;
        service.submit({large}, {}, 5);
        QTRY_VERIFY_WITH_TIMEOUT(first.expired(), 5000);
    }
    void queuePressurePublishesLimitedResult() {
        ApplicationAnalysisService service;
        auto packet = std::make_shared<Packet>(decodeSummary(fixtures::icmp()));
        packet->id = 1;
        packet->estimatedBytes = applicationQueueBudget + 1;
        QSignalSpy changed(&service, &ApplicationAnalysisService::changed);
        service.submit({packet}, {});
        QVERIFY(!changed.empty());
        const auto results = service.takeResults();
        QCOMPARE(results.size(), 1u);
        QCOMPARE(results.front().facts.at(1).status, AnalysisStatus::Limited);
        QVERIFY(!service.busy());
    }
    void indexesOnlyCarrierPackets() {
        SessionStore store;
        traffic(store);
        ApplicationAnalysisService service;
        QSignalSpy changed(&service, &ApplicationAnalysisService::changed);
        service.submit({store.packets().begin(), store.packets().end()}, connections(store));
        QTRY_VERIFY_WITH_TIMEOUT(changed.size() > 0 && !service.busy(), 5000);
        auto results = service.takeResults();
        QCOMPARE(results.size(), 1u);
        QCOMPARE(results[0].generation, service.generation());
        ApplicationIndex index;
        index.apply(results[0].conversation, results[0].result, std::move(results[0].facts));
        const auto filter = compileDisplayFilter("http.host == \"example.com\"").value;
        QCOMPARE(filter->evaluate(*store.packets()[0], index.facts(1)), FilterTruth::False);
        QCOMPARE(filter->evaluate(*store.packets()[3], index.facts(4)), FilterTruth::True);
        QVERIFY(index.estimatedBytes() < applicationBudget);
        index.prune(4, 4);
        QVERIFY(!index.facts(1));
        QVERIFY(index.facts(4));
        index.clear();
        QCOMPARE(index.estimatedBytes(), 0u);
    }
    void resetRejectsSlowResult() {
        auto entered = std::make_shared<std::atomic<bool>>(false);
        ApplicationHooks hooks;
        hooks.conversation = [entered](const TcpStreamRequest &, const TlsKeyLog &,
                                       std::stop_token stop) {
            *entered = true;
            while (!stop.stop_requested())
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            return ApplicationResult{};
        };
        ApplicationAnalysisService service(nullptr, hooks);
        SessionStore store;
        traffic(store);
        service.submit({store.packets().begin(), store.packets().end()}, connections(store));
        QTRY_VERIFY_WITH_TIMEOUT(entered->load(), 5000);
        const auto before = service.generation();
        service.reset();
        QVERIFY(service.generation() > before);
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        QVERIFY(service.takeResults().empty());
    }
    void keyFileErrorsKeepWorkerAvailable() {
        QTemporaryDir directory;
        const auto path = directory.filePath("keys.log");
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("invalid\n");
        file.close();
        ApplicationAnalysisService service;
        QSignalSpy keys(&service, &ApplicationAnalysisService::keyLogChanged);
        service.setKeyLog(path);
        QTRY_COMPARE_WITH_TIMEOUT(keys.size(), 1, 5000);
        QCOMPARE(keys.front()[0].toBool(), false);
        service.setKeyLog({});
        QTRY_COMPARE_WITH_TIMEOUT(keys.size(), 2, 5000);
        QCOMPARE(keys.back()[0].toBool(), true);
        SessionStore store;
        traffic(store);
        service.submit({store.packets().begin(), store.packets().end()}, connections(store));
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 5000);
        QVERIFY(!service.takeResults().empty());
    }
};
QTEST_GUILESS_MAIN(ApplicationServiceTests)
#include "application_service_tests.moc"
