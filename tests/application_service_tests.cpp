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
void traffic(SessionStore& store){const std::string request="GET /index HTTP/1.1\r\nHost: example.com\r\n\r\n";for(auto raw:{fixtures::tcp(2,99),fixtures::tcp(18,499,100,true),fixtures::tcp(16,100,500),fixtures::tcp(24,100,500,false,50000,false,{request.begin(),request.end()})})store.append(decodeSummary(std::move(raw)));}
std::vector<TcpConversation> connections(const SessionStore& store){return {store.tcp().items().begin(),store.tcp().items().end()};}
}
class ApplicationServiceTests:public QObject {
    Q_OBJECT
private slots:
    void rejectedBatchStillReleasesEvictedPackets(){
        ApplicationAnalysisService service;SessionStore store;traffic(store);std::weak_ptr<const Packet> first=store.packets().front();
        service.submit({store.packets().begin(),store.packets().end()},connections(store),1);QTRY_VERIFY_WITH_TIMEOUT(!service.busy(),5000);store.clear();QVERIFY(!first.expired());
        auto large=std::make_shared<Packet>(decodeSummary(fixtures::icmp()));large->id=5;large->estimatedBytes=applicationQueueBudget+1;
        service.submit({large},{},5);QTRY_VERIFY_WITH_TIMEOUT(first.expired(),5000);
    }
    void queuePressurePublishesLimitedResult(){
        ApplicationAnalysisService service;auto packet=std::make_shared<Packet>(decodeSummary(fixtures::icmp()));packet->id=1;packet->estimatedBytes=applicationQueueBudget+1;
        QSignalSpy changed(&service,&ApplicationAnalysisService::changed);service.submit({packet},{});QVERIFY(!changed.empty());
        const auto results=service.takeResults();QCOMPARE(results.size(),1u);QCOMPARE(results.front().facts.at(1).status,AnalysisStatus::Limited);QVERIFY(!service.busy());
    }
    void indexesOnlyCarrierPackets(){
        SessionStore store;traffic(store);ApplicationAnalysisService service;QSignalSpy changed(&service,&ApplicationAnalysisService::changed);service.submit({store.packets().begin(),store.packets().end()},connections(store));QTRY_VERIFY_WITH_TIMEOUT(changed.size()>0 && !service.busy(),5000);
        auto results=service.takeResults();QCOMPARE(results.size(),1u);QCOMPARE(results[0].generation,service.generation());ApplicationIndex index;index.apply(results[0].conversation,results[0].result,std::move(results[0].facts));
        const auto filter=compileDisplayFilter("http.host == \"example.com\"").value;QCOMPARE(filter->evaluate(*store.packets()[0],index.facts(1)),FilterTruth::False);QCOMPARE(filter->evaluate(*store.packets()[3],index.facts(4)),FilterTruth::True);QVERIFY(index.estimatedBytes()<applicationBudget);
        index.prune(4,4);QVERIFY(!index.facts(1));QVERIFY(index.facts(4));index.clear();QCOMPARE(index.estimatedBytes(),0u);
    }
    void resetRejectsSlowResult(){
        auto entered=std::make_shared<std::atomic<bool>>(false);ApplicationHooks hooks;hooks.conversation=[entered](const TcpStreamRequest&,const TlsKeyLog&,std::stop_token stop){*entered=true;while(!stop.stop_requested())std::this_thread::sleep_for(std::chrono::milliseconds(1));return ApplicationResult{};};
        ApplicationAnalysisService service(nullptr,hooks);SessionStore store;traffic(store);service.submit({store.packets().begin(),store.packets().end()},connections(store));QTRY_VERIFY_WITH_TIMEOUT(entered->load(),5000);const auto before=service.generation();service.reset();QVERIFY(service.generation()>before);QTRY_VERIFY_WITH_TIMEOUT(!service.busy(),5000);QVERIFY(service.takeResults().empty());
    }
    void keyFileErrorsKeepWorkerAvailable(){
        QTemporaryDir directory;const auto path=directory.filePath("keys.log");QFile file(path);QVERIFY(file.open(QIODevice::WriteOnly));file.write("invalid\n");file.close();ApplicationAnalysisService service;QSignalSpy keys(&service,&ApplicationAnalysisService::keyLogChanged);service.setKeyLog(path);QTRY_COMPARE_WITH_TIMEOUT(keys.size(),1,5000);QCOMPARE(keys.front()[0].toBool(),false);
        service.setKeyLog({});QTRY_COMPARE_WITH_TIMEOUT(keys.size(),2,5000);QCOMPARE(keys.back()[0].toBool(),true);SessionStore store;traffic(store);service.submit({store.packets().begin(),store.packets().end()},connections(store));QTRY_VERIFY_WITH_TIMEOUT(!service.busy(),5000);QVERIFY(!service.takeResults().empty());
    }
};
QTEST_GUILESS_MAIN(ApplicationServiceTests)
#include "application_service_tests.moc"
