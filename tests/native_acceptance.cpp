#include "ui/main_window.h"
#include "ui/application_view.h"
#include "ui/analysis_dock.h"
#include "ui/language.h"
#include "fixtures.h"
#include <QApplication>
#include <QAction>
#include <QComboBox>
#include <QFile>
#include <QFileInfo>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QPushButton>
#include <QScreen>
#include <QSettings>
#include <QSignalSpy>
#include <QSplitter>
#include <QTableView>
#include <QTemporaryDir>
#include <QTest>
#include <QTreeWidget>
#include <QElapsedTimer>
using namespace etherscope;
namespace {
void seedPackets(MainWindow &window) {
    const std::string request="GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    std::vector<Packet> packets;
    for (auto raw : {fixtures::tcp(2,99),fixtures::tcp(18,499,100,true),fixtures::tcp(16,100,500),
                     fixtures::tcp(24,100,500,false,50000,false,{request.begin(),request.end()})})
        packets.push_back(decodeSummary(std::move(raw)));
    window.ingestBenchmark(std::move(packets)); window.selectPacket(3);
}
void report(const QString &path, const QJsonObject &data) {
    QFile out(path); if (!out.open(QIODevice::WriteOnly)) qFatal("Cannot write native acceptance evidence");
    out.write(QJsonDocument(data).toJson());
}
}
class NativeAcceptance final : public QObject {
    Q_OBJECT
private slots:
    void seedUpgradeSettings() {
        const auto path=qEnvironmentVariable("ETHERSCOPE_ACCEPTANCE_SETTINGS"); QVERIFY(!path.isEmpty());
        { QSettings settings(path,QSettings::IniFormat); settings.remove("filter"); settings.setValue("capture/device","\\Device\\NPF_Loopback");
          settings.setValue("capture/bpf","tcp"); settings.setValue("filter/expression","tcp"); }
        MainWindowOptions options; options.settingsFile=path; options.language="zh_TW";
        options.capture.interfaces=[](QString &) { return std::vector<CaptureInterface>{{"\\Device\\NPF_Loopback","Loopback","127.0.0.1"}}; };
        {
            MainWindow window(nullptr,options); window.resize(1200,780); window.move(40,40); window.show();
            QTRY_VERIFY(!window.discovering()); window.setDarkTheme(false);
            window.findChild<QTableView *>("packetTable")->setColumnWidth(0,77);
            window.findChild<QTableView *>("packetTable")->setColumnWidth(2,210);
            window.findChild<QSplitter *>("fieldHexSplitter")->setSizes({480,720});
            seedPackets(window); QTRY_VERIFY(!window.applicationBusy());
            window.findChild<QAction *>("tcpConversationsAction")->trigger();
            window.findChild<QAction *>("applicationAnalysisAction")->trigger();
            QVERIFY(window.close());
        }
        QSettings settings(path,QSettings::IniFormat);
        QWidget geometry; geometry.resize(820,560); geometry.move(40000,40000);
        for (const auto *name : {"tcpAnalysisDock","applicationAnalysisDock"}) {
            const auto prefix=QString("ui/analysis/v1/")+name+'/';
            settings.setValue(prefix+"floating",true); settings.setValue(prefix+"area",int(Qt::BottomDockWidgetArea));
            settings.setValue(prefix+"extent",410); settings.setValue(prefix+"geometry",geometry.saveGeometry());
        }
        settings.sync(); QCOMPARE(settings.status(),QSettings::NoError);
    }
    void upgradedSettingsRestore() {
        MainWindowOptions options; options.settingsFile=qEnvironmentVariable("ETHERSCOPE_ACCEPTANCE_SETTINGS");
        QVERIFY(!options.settingsFile.isEmpty());
        MainWindow window(nullptr,options); window.show(); QTRY_VERIFY(!window.discovering());
        QCOMPARE(i18n::language().current(),QString("zh_TW"));
        QVERIFY(window.palette().color(QPalette::Base).lightness()>128);
        QCOMPARE(window.size(),QSize(1200,780));
        QCOMPARE(window.findChild<QTableView *>("packetTable")->columnWidth(0),77);
        QCOMPARE(window.findChild<QTableView *>("packetTable")->columnWidth(2),210);
        QCOMPARE(window.findChild<QLineEdit *>("expressionInput")->text(),QString("tcp"));
        auto *device=window.findChild<QComboBox *>("deviceSelector");
        QCOMPARE(device->currentData().toString(),QString("\\Device\\NPF_Loopback"));
        { QSettings settings(options.settingsFile,QSettings::IniFormat); QCOMPARE(settings.value("capture/bpf").toString(),QString("tcp")); }
        const auto sizes=window.findChild<QSplitter *>("fieldHexSplitter")->sizes();
        const auto fraction=double(sizes[0])/(sizes[0]+sizes[1]); QVERIFY(fraction>.35 && fraction<.45);
        seedPackets(window); QTRY_VERIFY(!window.applicationBusy());
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
        window.findChild<QAction *>("applicationAnalysisAction")->trigger();
        for (const auto *name : {"tcpAnalysisDock","applicationAnalysisDock"}) {
            auto *dock=window.findChild<AnalysisDock *>(name); QVERIFY(dock); QVERIFY(dock->isFloating());
            QTest::qWait(50);
            const auto area=QGuiApplication::primaryScreen()->availableGeometry();
            QVERIFY(area.intersects(dock->frameGeometry())); QVERIFY(area.contains(dock->frameGeometry().center()));
        }
        report(qEnvironmentVariable("ETHERSCOPE_ACCEPTANCE_REPORT"),{{"settings_restored",true},{"offscreen_geometry_recovered",true},
            {"language","zh_TW"},{"theme","light"},{"bpf","tcp"},{"columns",true},{"splitters",true},{"docks",true},{"passed",true}});
        QVERIFY(window.close());
    }
    void realLoopbackCaptureAndAnalysis() {
        QTemporaryDir temporary; QVERIFY(temporary.isValid());
        const auto port=qEnvironmentVariable("ETHERSCOPE_HTTP_PORT"); QVERIFY(!port.isEmpty());
        const auto bpf="tcp port "+port+" and host 127.0.0.1";
        const auto settings=temporary.filePath("settings.ini");
        { QSettings config(settings,QSettings::IniFormat); config.setValue("capture/device","\\Device\\NPF_Loopback"); config.setValue("capture/bpf",bpf); }
        MainWindowOptions options; options.settingsFile=settings; options.language="en";
        MainWindow window(nullptr,options); window.resize(1200,780); window.show();
        QTRY_VERIFY(!window.discovering());
        auto *device=window.findChild<QComboBox *>("deviceSelector");
        const auto index=device->findData("\\Device\\NPF_Loopback"); QVERIFY2(index>=0,"Npcap loopback adapter missing"); device->setCurrentIndex(index);
        window.findChild<QPushButton *>("startButton")->click();
        QTRY_COMPARE_WITH_TIMEOUT(window.captureState(),MainWindow::CaptureState::Running,10000);
        { QFile ready(qEnvironmentVariable("ETHERSCOPE_ACCEPTANCE_READY")); QVERIFY(ready.open(QIODevice::WriteOnly)); ready.write("ready"); }
        QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(qEnvironmentVariable("ETHERSCOPE_ACCEPTANCE_DONE")),15000);
        QTRY_VERIFY_WITH_TIMEOUT(window.captureCounters().received>=20,15000);
        QTRY_VERIFY_WITH_TIMEOUT(window.applicationIndex().diagnostics().count(AnalysisStatus::Complete)>0,10000);
        QElapsedTimer stop; stop.start(); window.stopCapture(); QTRY_VERIFY_WITH_TIMEOUT(!window.busy(),5000); const auto stopMs=stop.elapsed();
        QTRY_VERIFY_WITH_TIMEOUT(!window.applicationBusy(),5000);
        QVERIFY(window.applyExpression("http.host == \"localhost\"")); QTRY_VERIFY(window.packetModel()->rowCount()>0);
        const auto filtered=window.packetModel()->rowCount(); window.selectPacket(0);
        window.findChild<QAction *>("applicationAnalysisAction")->trigger();
        auto *view=window.findChild<AnalysisDock *>("applicationAnalysisDock")->findChild<ApplicationView *>(); QVERIFY(view);
        QTRY_VERIFY(!view->updating());
        auto *messages=view->findChild<QTreeWidget *>("applicationMessages"); QTRY_VERIFY(messages->topLevelItemCount()>0);
        auto *locate=view->findChild<QPushButton *>("applicationLocate"); QTRY_VERIFY(locate->isEnabled()); locate->click();
        const auto capture=window.captureCounters(); QCOMPARE(capture.queueDropped,0ULL); QVERIFY(stopMs<=1000);
        const auto saved=qEnvironmentVariable("ETHERSCOPE_ACCEPTANCE_PCAPNG"); QVERIFY(!saved.isEmpty());
        QSignalSpy exported(&window,&MainWindow::saveFinished); QVERIFY(window.saveFile(saved,CaptureFormat::Pcapng));
        QTRY_COMPARE_WITH_TIMEOUT(exported.count(),1,10000); QVERIFY(exported[0][0].toBool());
        QSignalSpy opened(&window,&MainWindow::fileOpenFinished); QVERIFY(window.openFile(saved));
        QTRY_COMPARE_WITH_TIMEOUT(opened.count(),1,10000); QTRY_VERIFY_WITH_TIMEOUT(!window.applicationBusy(),10000);
        QTRY_VERIFY(window.packetModel()->rowCount()>0);
        report(qEnvironmentVariable("ETHERSCOPE_ACCEPTANCE_REPORT"),{{"kind","native_ui_controlled_loopback_http"},
            {"received",double(capture.received)},{"queue_dropped",double(capture.queueDropped)},{"bpf",bpf},
            {"filtered_rows",filtered},{"stop_ms",double(stopMs)},{"analysis",true},{"locate",true},{"pcapng_reopened",true},{"passed",true}});
        QVERIFY(window.close());
    }
};
QTEST_MAIN(NativeAcceptance)
#include "native_acceptance.moc"
