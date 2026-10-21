#include "capture/recording.h"
#include "core/capture_file.h"
#include "fixtures.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>
#include <atomic>

using namespace etherscope;
class RecordingTests:public QObject {
    Q_OBJECT
private slots:
    void rotatesWithinBudget() {
        QTemporaryDir directory;RecordingService service;RecordingOptions options;options.enabled=true;options.directory=directory.path();options.fileBytes=512;options.diskBytes=1536;
        QFile unrelated(directory.filePath("keep.pcapng"));QVERIFY(unrelated.open(QIODevice::WriteOnly));unrelated.write("keep");unrelated.close();
        QSignalSpy finished(&service,&RecordingService::finished);QVERIFY(service.start(options));for(int i=0;i<60;++i){auto raw=fixtures::icmp();raw.timestampNs+=i;service.submit(raw);}service.finish();QTRY_COMPARE_WITH_TIMEOUT(finished.size(),1,10000);
        const auto stats=service.stats();QVERIFY(!stats.failed);QCOMPARE(stats.written,60ULL);QCOMPARE(stats.unwritten,0ULL);QVERIFY(stats.diskBytes<=options.diskBytes);
        const auto files=QDir(stats.directory).entryList({"*.pcapng"},QDir::Files,QDir::Name);QVERIFY(files.size()>1);QVERIFY(QDir(stats.directory).entryList({"*.part"},QDir::Files).empty());
        std::int64_t previous=-1;std::size_t count=0;quint64 bytes=0;
        for(const auto& name:files){const auto path=QDir(stats.directory).filePath(name);bytes+=QFileInfo(path).size();CaptureReader reader(std::filesystem::path(path.toStdWString()));while(auto raw=reader.next()){QVERIFY(raw->timestampNs>previous);previous=raw->timestampNs;QCOMPARE(raw->bytes,fixtures::icmp().bytes);++count;}}
        QVERIFY(count>0 && count<60);QVERIFY(bytes<=options.diskBytes);QVERIFY(unrelated.open(QIODevice::ReadOnly));QCOMPARE(unrelated.readAll(),QByteArray("keep"));
    }
    void writeFailure() {
        QTemporaryDir directory;RecordingHooks hooks;hooks.write=[](QIODevice&,const char*,qint64){return qint64(-1);};RecordingService service(nullptr,hooks);RecordingOptions options;options.enabled=true;options.directory=directory.path();QSignalSpy finished(&service,&RecordingService::finished);QVERIFY(service.start(options));service.submit(fixtures::icmp());service.finish();QTRY_COMPARE_WITH_TIMEOUT(finished.size(),1,5000);const auto stats=service.stats();QVERIFY(stats.failed);QCOMPARE(stats.written,0ULL);QCOMPARE(stats.unwritten,1ULL);QVERIFY(!QDir(stats.directory).entryList({"*.part"},QDir::Files).empty());
    }
    void deletionFailure() {
        QTemporaryDir directory;RecordingHooks hooks;hooks.remove=[](const QString&){return false;};RecordingService service(nullptr,hooks);RecordingOptions options;options.enabled=true;options.directory=directory.path();options.fileBytes=512;options.diskBytes=1024;QSignalSpy finished(&service,&RecordingService::finished);QVERIFY(service.start(options));for(int i=0;i<100;++i)service.submit(fixtures::icmp());service.finish();QTRY_COMPARE_WITH_TIMEOUT(finished.size(),1,5000);const auto stats=service.stats();QVERIFY(stats.failed);QVERIFY(stats.written>0);QCOMPARE(stats.written+stats.unwritten,100ULL);
    }
    void overflowDoesNotBlockEventLoop() {
        struct Gate {std::mutex mutex;std::condition_variable wake;bool released{};std::atomic<bool> entered{};};auto gate=std::make_shared<Gate>();
        struct Release {std::shared_ptr<Gate> gate;~Release(){{std::lock_guard lock(gate->mutex);gate->released=true;}gate->wake.notify_all();}};
        QTemporaryDir directory;RecordingHooks hooks;hooks.write=[gate](QIODevice& device,const char* bytes,qint64 size){gate->entered=true;std::unique_lock lock(gate->mutex);gate->wake.wait(lock,[&]{return gate->released;});return device.write(bytes,size);};
        RecordingService service(nullptr,hooks);Release release{gate};RecordingOptions options;options.enabled=true;options.directory=directory.path();options.fileBytes=1024*1024;options.diskBytes=4*1024*1024;QSignalSpy finished(&service,&RecordingService::finished);QVERIFY(service.start(options));auto large=fixtures::icmp();large.bytes.resize(65535);large.originalLength=65535;service.submit(large);QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(),5000);
        for(int i=0;i<8193;++i)service.submit(fixtures::icmp());QVERIFY(service.stats().failed);int beats=0;QTimer timer;connect(&timer,&QTimer::timeout,[&]{++beats;});timer.start(5);QTRY_VERIFY_WITH_TIMEOUT(beats>=3,1000);
        {std::lock_guard lock(gate->mutex);gate->released=true;}gate->wake.notify_all();QTRY_COMPARE_WITH_TIMEOUT(finished.size(),1,10000);QCOMPARE(service.stats().written+service.stats().unwritten,8194ULL);
    }
};
QTEST_GUILESS_MAIN(RecordingTests)
#include "recording_tests.moc"
