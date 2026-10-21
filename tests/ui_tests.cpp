#include "ui/main_window.h"
#include "ui/tcp_dialog.h"
#include "ui/stream_pane.h"
#include "ui/application_view.h"
#include "ui/language.h"
#include <QCheckBox>
#include <QAction>
#include <QDialog>
#include <QMenu>
#include <QIcon>
#include <QFileDialog>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableView>
#include <QTabBar>
#include <QTabWidget>
#include <QTreeWidget>
#include "fixtures.h"
#include "core/pcap_file.h"
#include "version.h"
#include <QStyleFactory>
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTest>
#include <QSignalSpy>
#include <QElapsedTimer>
#include <QFontDatabase>
#include <QAbstractItemModelTester>
#include <QPersistentModelIndex>
#include <QSettings>
#include <QJsonDocument>
#include <QJsonArray>
#include <QRegularExpression>
#include <QScreen>
#include <QScrollBar>
#include <QSplitter>
#include <QHeaderView>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <fstream>

using namespace etherscope;
namespace {
MainWindowOptions testOptions() {
    static QTemporaryDir directory;
    static int id = 0;
    MainWindowOptions options;
    options.settingsFile = directory.filePath(QString::number(++id) + ".ini");
    // Keep exported test screenshots independent of this computer's adapter names and addresses.
    options.capture.interfaces = [](QString &error) {
        error.clear();
        return std::vector<CaptureInterface>{{"test-interface", "测试网卡（构造）", "192.0.2.1"}};
    };
    return options;
}
bool waitForInterfaces(MainWindow &window) {
    QElapsedTimer deadline;
    deadline.start();
    while (window.discovering() && deadline.elapsed() < 5000)
        QTest::qWait(1);
    return !window.discovering();
}
bool waitForDetails(MainWindow &window) {
    QElapsedTimer deadline;
    deadline.start();
    while (window.detailsBusy() && deadline.elapsed() < 5000)
        QTest::qWait(1);
    return !window.detailsBusy();
}
bool setBpf(MainWindow &window, const QString &expression) {
    window.findChild<QAction *>("captureFilterAction")->trigger();
    auto *input = window.findChild<QLineEdit *>("bpfInput");
    if (!input || input->isReadOnly())
        return false;
    input->setText(expression);
    window.findChild<QPushButton *>("applyBpfButton")->click();
    QTest::qWait(1);
    return true;
}
struct Gate {
    std::mutex mutex;
    std::condition_variable cv;
    bool released = false;
    std::atomic<bool> entered{};
    void wait() {
        entered = true;
        std::unique_lock lock(mutex);
        cv.wait(lock, [this] { return released; });
    }
    void release() {
        {
            std::lock_guard lock(mutex);
            released = true;
        }
        cv.notify_all();
    }
};
struct ReleaseGate {
    std::shared_ptr<Gate> gate;
    ~ReleaseGate() {
        gate->release();
    }
};
CaptureHooks fakeCapture(std::shared_ptr<Gate> starting = {},
                         std::shared_ptr<Gate> fileStarting = {},
                         std::shared_ptr<std::atomic<int>> starts = {}) {
    CaptureHooks hooks;
    hooks.interfaces = [](QString &error) {
        error.clear();
        return std::vector<CaptureInterface>{{"fake-a", "测试网卡 A", "192.0.2.1"},
                                             {"fake-b", "测试网卡 B", "192.0.2.2"}};
    };
    hooks.run = [starting, fileStarting,
                 starts](const QString &target, bool file, std::stop_token stop,
                         const CaptureHooks::Sink &sink, const CaptureHooks::Opened &opened,
                         const LiveCaptureOptions &) {
        if (starts)
            ++*starts;
        if (file) {
            if (fileStarting)
                fileStarting->wait();
            PcapReader reader(std::filesystem::path(target.toStdWString()));
            opened("测试文件读取");
            while (!stop.stop_requested()) {
                auto raw = reader.next();
                if (!raw)
                    break;
                sink(std::move(*raw));
            }
            return;
        }
        if (starting)
            starting->wait();
        opened("捕获中");
        auto raw = fixtures::icmp();
        while (!stop.stop_requested()) {
            raw.timestampNs += 1000000;
            sink(raw);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    };
    return hooks;
}
ExportWriter gatedWriter(std::shared_ptr<Gate> gate, bool fail = false) {
    return [gate, fail](QIODevice &file, const char *data, qint64 n) {
        gate->wait();
        return fail ? qint64(-1) : file.write(data, n);
    };
}
QString sampleFile(QTemporaryDir &directory) {
    const auto path = directory.filePath("input.pcap");
    std::vector<Packet> packets;
    for (auto raw : fixtures::samples())
        packets.push_back(decodePacket(std::move(raw)));
    std::vector<const Packet *> refs;
    for (const auto &packet : packets)
        refs.push_back(&packet);
    std::ofstream out(std::filesystem::path(path.toStdWString()), std::ios::binary);
    writePcap(out, refs);
    return path;
}
void ingestStream(MainWindow &window) {
    std::vector<Packet> packets;
    for (auto raw : fixtures::tcpStreamSamples())
        packets.push_back(decodeSummary(std::move(raw)));
    window.ingestBenchmark(std::move(packets));
}
TcpDialog *startStream(MainWindow &window) {
    window.findChild<QAction *>("tcpConversationsAction")->trigger();
    auto *dialog = window.findChild<TcpDialog *>();
    dialog->selectConversation(1);
    dialog->findChild<QPushButton *>("tcpStreamButton")->click();
    return dialog;
}
} // namespace
class DesktopTests : public QObject {
    Q_OBJECT
  private slots:
    void applicationUpdatesKeepLiveFollowing() {
        auto advance = std::make_shared<std::atomic<bool>>(false);
        auto options = testOptions();
        options.capture = fakeCapture();
        options.capture.run =
            [advance](const QString &, bool, std::stop_token stop, const CaptureHooks::Sink &sink,
                      const CaptureHooks::Opened &opened, const LiveCaptureOptions &) {
                opened("捕获中");
                for (auto raw : {fixtures::tcp(2, 99), fixtures::tcp(18, 499, 100, true),
                                 fixtures::tcp(16, 100, 500)})
                    sink(std::move(raw));
                const std::string request = "GET / HTTP/1.1\r\nHost: following.example\r\n\r\n";
                const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                std::uint32_t client = 100, server = 500;
                auto round = [&] {
                    sink(fixtures::tcp(24, client, server, false, 50000, false,
                                       {request.begin(), request.end()}));
                    client += static_cast<std::uint32_t>(request.size());
                    sink(fixtures::tcp(24, server, client, true, 50000, false,
                                       {response.begin(), response.end()}));
                    server += static_cast<std::uint32_t>(response.size());
                };
                for (unsigned i = 0; i < 128 && !stop.stop_requested(); ++i)
                    round();
                while (!advance->load() && !stop.stop_requested())
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                for (unsigned i = 0; i < 1200 && !stop.stop_requested(); ++i)
                    round();
                while (!stop.stop_requested())
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            };
        MainWindow window(nullptr, options);
        window.show();
        QVERIFY(waitForInterfaces(window));
        QVERIFY(window.applyExpression("http.host"));
        auto *follow = window.findChild<QCheckBox *>("followLatest");
        follow->setChecked(true);
        window.findChild<QPushButton *>("startButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(window.packetModel()->rowCount() > 0, 10000);
        window.selectPacket(0);
        follow->setChecked(true);
        advance->store(true);
        QTRY_VERIFY_WITH_TIMEOUT(window.captureCounters().received >= 2659, 10000);
        window.stopCapture();
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy() && !window.applicationBusy(), 10000);
        QVERIFY(follow->isChecked());
        auto *table = window.findChild<QTableView *>("packetTable");
        QVERIFY(table);
        QTRY_COMPARE(table->verticalScrollBar()->value(), table->verticalScrollBar()->maximum());
    }
    void applicationDeltaEvaluatesOnlyChangedPackets() {
        SessionStore store;
        ApplicationIndex applications;
        PacketModel model(&store);
        model.setApplicationIndex(&applications);
        QAbstractItemModelTester tester(&model,
                                        QAbstractItemModelTester::FailureReportingMode::QtTest);
        std::vector<Packet> packets;
        for (unsigned i = 0; i < 10000; ++i)
            packets.push_back(decodeSummary(fixtures::icmp()));
        model.append(std::move(packets));
        model.setExpression(compileDisplayFilter("http.host == \"example.com\"").value);
        QCOMPARE(model.rowCount(), 0);
        auto result = std::make_shared<ApplicationResult>();
        ApplicationFacts facts;
        facts.status = AnalysisStatus::Complete;
        facts.values["http.host"] = {std::string("example.com")};
        IndexDelta changes;
        applications.apply(1, result, {{5000, facts}}, &changes);
        const auto before = model.evaluations();
        model.refreshApplications(changes);
        QCOMPARE(model.evaluations() - before, 1ULL);
        QCOMPARE(model.rowCount(), 1);
        QCOMPARE(model.packetAt(0)->id, 5000ULL);
        QPersistentModelIndex selected = model.index(0, 0);
        changes.packets.clear();
        applications.apply(2, result, {{7500, facts}}, &changes);
        const auto next = model.evaluations();
        model.refreshApplications(changes);
        QCOMPARE(model.evaluations() - next, 1ULL);
        QCOMPARE(model.rowCount(), 2);
        QVERIFY(selected.isValid());
        QCOMPARE(selected.row(), 0);
        model.refreshApplications();
        QCOMPARE(model.rowCount(), 2);
        changes.packets.clear();
        applications.prune(6000, 10000, &changes);
        model.refreshApplications(changes);
        QCOMPARE(model.rowCount(), 1);
        QCOMPARE(model.packetAt(0)->id, 7500ULL);
    }
    void recordingCloseWaitsAndFailureKeepsWindow() {
        for (bool fail : {false, true}) {
            QTemporaryDir directory;
            auto options = testOptions();
            options.capture = fakeCapture();
            {
                QSettings settings(options.settingsFile, QSettings::IniFormat);
                settings.setValue("recording/directory", directory.path());
            }
            auto gate = std::make_shared<Gate>();
            options.recording.write = gatedWriter(gate, fail);
            MainWindow window(nullptr, options);
            ReleaseGate release{gate};
            window.show();
            QVERIFY(waitForInterfaces(window));
            window.findChild<QAction *>("recordingAction")->setChecked(true);
            window.findChild<QPushButton *>("startButton")->click();
            QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 5000);
            QVERIFY(window.recordingBusy());
            QVERIFY(!window.close());
            QVERIFY(window.isVisible());
            int beats = 0;
            QTimer timer;
            connect(&timer, &QTimer::timeout, [&] { ++beats; });
            timer.start(5);
            QTRY_VERIFY_WITH_TIMEOUT(beats >= 3, 1000);
            QTRY_VERIFY_WITH_TIMEOUT(!window.busy() && !window.applicationBusy(), 5000);
            gate->release();
            if (fail) {
                auto *recording = window.findChild<RecordingService *>();
                QVERIFY(recording);
                QElapsedTimer finished;
                finished.start();
                while (recording->running() && finished.elapsed() < 5000)
                    QTest::qSleep(1);
                QVERIFY(!recording->running());
                // The failure notification is queued but has not reached the window yet.
                QVERIFY(!window.close());
                QVERIFY(window.isVisible());
            }
            QTRY_VERIFY_WITH_TIMEOUT(!window.recordingBusy() && !window.busy(), 5000);
            if (fail) {
                QVERIFY(window.recordingStats().failed);
                QVERIFY(window.isVisible());
                QVERIFY(window.packetModel()->rowCount() > 0);
            } else {
                QTRY_VERIFY_WITH_TIMEOUT(!window.isVisible(), 5000);
                QVERIFY(!window.recordingStats().failed);
                QVERIFY(window.recordingStats().written > 0);
            }
        }
    }
    void applicationViewKeepsSelectionAndLocatesBytes() {
        ApplicationView view;
        QCOMPARE(view.findChild<QLabel *>("applicationState")->text(),
                 i18n::text("Pending analysis"));
        auto result = std::make_shared<ApplicationResult>();
        ApplicationMessage message;
        message.protocol = "HTTP";
        message.bytes = std::make_shared<const std::vector<std::uint8_t>>(64, 'x');
        message.length = 64;
        message.sources = {{7, 54, 32, 0}, {8, 54, 32, 32}};
        message.fields = {{"Host", "http.host", std::string("example.com"), 33, 5}};
        result->messages = {message, message};
        result->messages[1].offset = 1;
        view.setResults({result});
        view.show();
        auto *list = view.findChild<QTreeWidget *>("applicationMessages");
        auto *fields = view.findChild<QTreeWidget *>("applicationFields");
        auto *bytes = view.findChild<QPlainTextEdit *>("applicationBytes");
        QTRY_COMPARE(list->topLevelItemCount(), 2);
        list->setCurrentItem(list->topLevelItem(1));
        QTRY_COMPARE(fields->topLevelItemCount(), 1);
        fields->setCurrentItem(fields->topLevelItem(0));
        QVERIFY(!bytes->extraSelections().empty());
        QCOMPARE(bytes->extraSelections().front().cursor.selectedText(), QString("78 78 78 78 78"));
        auto *packets = view.findChild<QComboBox *>("applicationPackets");
        QCOMPARE(packets->count(), 1);
        QCOMPARE(packets->currentData().toULongLong(), 8ULL);
        auto *chosen = list->currentItem();
        view.setResults({result});
        QCOMPARE(list->currentItem(), chosen);
        QVERIFY(!bytes->extraSelections().empty());
        i18n::language().set("zh_TW");
        QTRY_COMPARE(list->topLevelItemCount(), 2);
        QCOMPARE(list->currentItem(), list->topLevelItem(1));
        QCOMPARE(view.findChild<QComboBox *>("applicationDataSource")->itemText(0),
                 QString("全部來源"));
    }
    void expressionUsesApplicationIndexAndKeepsDraft() {
        MainWindow window(nullptr, testOptions());
        window.show();
        const std::string request = "GET /index HTTP/1.1\r\nHost: example.com\r\n\r\n";
        std::vector<Packet> packets;
        for (auto raw :
             {fixtures::tcp(2, 99), fixtures::tcp(18, 499, 100, true), fixtures::tcp(16, 100, 500),
              fixtures::tcp(24, 100, 500, false, 50000, false, {request.begin(), request.end()})})
            packets.push_back(decodeSummary(std::move(raw)));
        QVERIFY(window.applyExpression("http.host == \"example.com\""));
        window.ingestBenchmark(std::move(packets));
        QTRY_COMPARE_WITH_TIMEOUT(window.packetModel()->rowCount(), 1, 5000);
        QCOMPARE(window.packetModel()->packetAt(0)->id, 4ULL);
        auto *input = window.findChild<QLineEdit *>("expressionInput");
        input->setText("tcp &&");
        QVERIFY(!window.applyExpression(input->text()));
        QCOMPARE(window.packetModel()->rowCount(), 1);
        QCOMPARE(input->text(), QString("tcp &&"));
        window.findChild<QPushButton *>("expressionCondition")->click();
        QCOMPARE(window.packetModel()->rowCount(), 4);
        window.selectPacket(3);
        window.findChild<QAction *>("applicationAnalysisAction")->trigger();
        QTRY_VERIFY_WITH_TIMEOUT(
            window.findChild<QTreeWidget *>("applicationMessages")->topLevelItemCount() > 0, 5000);
        QVERIFY(
            window.findChild<QPlainTextEdit *>("applicationBytes")->toPlainText().contains("GET"));
        auto *dialog = window.findChild<QDialog *>("applicationDialog");
        QVERIFY(dialog);
        for (const auto &language : {"en", "zh_CN", "zh_TW"})
            for (bool dark : {false, true})
                for (const QSize size : {QSize(1024, 768), QSize(1440, 900)}) {
                    i18n::language().set(language);
                    window.setDarkTheme(dark);
                    dialog->resize(size);
                    QTest::qWait(30);
                    auto *view = dialog->findChild<ApplicationView *>();
                    QVERIFY(view);
                    QVERIFY(dialog->rect().contains(
                        QRect(view->mapTo(dialog, QPoint(0, 0)), view->size())));
                    auto *fields = view->findChild<QTreeWidget *>("applicationFields");
                    QTRY_VERIFY(fields->topLevelItemCount() > 0);
                    QCOMPARE(fields->topLevelItem(0)->text(0),
                             QString(language == QString("en") ? "Method" : "方法"));
                    auto *bytes = view->findChild<QPlainTextEdit *>("applicationBytes");
                    QVERIFY(bytes->isVisible());
                    QVERIFY(bytes->width() >= 200);
                    const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
                    if (!screenshots.isEmpty())
                        QVERIFY(
                            dialog->grab().save(screenshots + QString("/application-%1-%2-%3.png")
                                                                  .arg(language)
                                                                  .arg(dark ? "dark" : "light")
                                                                  .arg(size.width())));
                }
    }
    void expressionRestoresOnlyValidCondition() {
        const auto options = testOptions();
        {
            MainWindow first(nullptr, options);
            QVERIFY(first.applyExpression("frame.len > 40"));
            first.findChild<QLineEdit *>("expressionInput")->setText("invalid_field");
            QVERIFY(!first.applyExpression("invalid_field"));
            first.setTlsKeyLog("C:/missing/key.log");
        }
        MainWindow second(nullptr, options);
        QVERIFY(second.packetModel()->expression());
        QCOMPARE(second.packetModel()->expression()->source(), std::string("frame.len > 40"));
        QSettings settings(options.settingsFile, QSettings::IniFormat);
        for (const auto &key : settings.allKeys())
            QVERIFY(!settings.value(key).toString().contains("C:/missing/key.log"));
    }
    void pcapngExportReopensWithoutChangingBytes() {
        MainWindow window(nullptr, testOptions());
        std::vector<Packet> packets;
        for (auto raw : fixtures::samples())
            packets.push_back(decodeSummary(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        QTemporaryDir directory;
        const auto path = directory.filePath("capture.pcapng");
        QSignalSpy saved(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(path));
        QTRY_COMPARE_WITH_TIMEOUT(saved.size(), 1, 5000);
        QVERIFY(saved.front()[0].toBool());
        CaptureReader reader(std::filesystem::path(path.toStdWString()));
        const auto original = fixtures::samples();
        for (const auto &raw : original) {
            const auto actual = reader.next();
            QVERIFY(actual);
            QCOMPARE(actual->bytes, raw.bytes);
            QCOMPARE(actual->timestampNs, raw.timestampNs);
        }
        QVERIFY(!reader.next());
    }
    void init() {
        i18n::language().set("zh_CN");
    }
    void languageSwitchPreservesAnalysis() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        ingestStream(window);
        window.selectPacket(8);
        QVERIFY(waitForDetails(window));
        auto *tree = window.findChild<QTreeWidget *>("fieldTree");
        const auto selected = window.packetModel()->packetAt(8);
        auto *input = window.findChild<QLineEdit *>("ipInput");
        input->setText("invalid IPv6 draft");
        auto *dialog = startStream(window);
        auto *pane = dialog->findChild<StreamPane *>();
        QTRY_VERIFY(pane->ready());
        const auto bytes = pane->findChild<QPlainTextEdit *>("streamBytes")->toPlainText();
        auto *table = window.findChild<QTableView *>("packetTable");
        QPersistentModelIndex index(table->currentIndex());
        QSignalSpy resets(window.packetModel(), &QAbstractItemModel::modelReset);
        for (const auto &code : {"en", "zh_TW", "zh_CN"}) {
            window.findChild<QAction *>("language_" + QString(code))->trigger();
            QCOMPARE(i18n::language().current(), QString(code));
            QCOMPARE(window.findChild<QPushButton *>("startButton")->text(),
                     code == QString("en")
                         ? QString("Start")
                         : QString("开始").replace("开", code == QString("zh_TW") ? "開" : "开"));
            QCOMPARE(input->text(), QString("invalid IPv6 draft"));
            QCOMPARE(window.packetModel()->packetAt(8), selected);
            QVERIFY(index.isValid());
            QCOMPARE(resets.count(), 0);
            QVERIFY(pane->ready());
            QCOMPARE(pane->findChild<QPlainTextEdit *>("streamBytes")->toPlainText(), bytes);
            QCOMPARE(
                window.packetModel()->headerData(2, Qt::Horizontal, Qt::DisplayRole).toString(),
                code == QString("en")
                    ? QString("Source")
                    : (code == QString("zh_TW") ? QString("來源位址") : QString("源地址")));
            QCOMPARE(tree->topLevelItem(0)->text(0), QString("Ethernet II"));
            if (code == QString("en")) {
                for (QTreeWidgetItemIterator item(tree); *item; ++item) {
                    QVERIFY(
                        !(*item)->text(0).contains(QRegularExpression("[\\x{4e00}-\\x{9fff}]")));
                    QVERIFY(
                        !(*item)->text(1).contains(QRegularExpression("[\\x{4e00}-\\x{9fff}]")));
                }
                QCOMPARE(pane->findChild<QLabel *>("streamPhase")->text(), QString("Reassembled"));
            }
        }
    }
    void languageSettingsAndExternalValues() {
        QTemporaryDir dir;
        auto options = testOptions();
        options.settingsFile = dir.filePath("language.ini");
        options.capture.interfaces = [](QString &error) {
            error.clear();
            return std::vector<CaptureInterface>{{"adapter-id", "保存 网卡 原名", "192.0.2.1"}};
        };
        {
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            window.show();
            window.findChild<QAction *>("language_zh_TW")->trigger();
            QCOMPARE(window.findChild<QComboBox *>("deviceSelector")->currentText(),
                     QString("保存 网卡 原名"));
        }
        {
            MainWindow window(nullptr, options);
            QCOMPARE(i18n::language().current(), QString("zh_TW"));
            QCOMPARE(window.findChild<QPushButton *>("saveButton")->text(), QString("儲存"));
        }
        {
            QSettings settings(options.settingsFile, QSettings::IniFormat);
            settings.setValue("ui/language", "invalid");
            settings.setValue("filter/protocol", "TCP");
        }
        {
            MainWindow window(nullptr, options);
            QCOMPARE(i18n::language().current(), QString("en"));
            QCOMPARE(window.packetModel()->filter().protocol, std::string("TCP"));
        }
        options.language = "zh-CN";
        {
            MainWindow window(nullptr, options);
            QCOMPARE(i18n::language().current(), QString("zh_CN"));
        }
        i18n::language().set("en");
        QCOMPARE(i18n::errorText("无法打开接口: 保存 网卡.pcap"),
                 QString("Cannot open interface: 保存 网卡.pcap"));
        QCOMPARE(i18n::normalize("zh-Hant-TW"), QString("zh_TW"));
        QCOMPARE(i18n::normalize("en-US"), QString("en"));
        QVERIFY(!i18n::language().set("unsupported"));
        QCOMPARE(i18n::language().current(), QString("en"));
    }
    void languageDuringCaptureAndSave() {
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.capture = fakeCapture();
        options.exportWriter = gatedWriter(gate);
        MainWindow window(nullptr, options);
        ReleaseGate release{gate};
        QVERIFY(waitForInterfaces(window));
        window.show();
        window.findChild<QPushButton *>("startButton")->click();
        QTRY_VERIFY(window.captureCounters().received > 25);
        QTemporaryDir dir;
        QSignalSpy saved(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(dir.filePath("网卡 保存.pcap")));
        QTRY_VERIFY(gate->entered.load());
        const auto before = window.captureCounters().received;
        i18n::language().set("en");
        QVERIFY(window.findChild<QLabel *>("exportProgress")->text().startsWith("Saving"));
        QTRY_VERIFY(window.captureCounters().received > before + 25);
        QCOMPARE(window.captureState(), MainWindow::CaptureState::Running);
        i18n::language().set("zh_TW");
        QVERIFY(window.findChild<QLabel *>("exportProgress")->text().startsWith("儲存中"));
        gate->release();
        QTRY_COMPARE(saved.count(), 1);
        QVERIFY(saved[0][0].toBool());
        QCOMPARE(saved[0][1].toString(), dir.filePath("网卡 保存.pcap"));
        window.stopCapture();
        QTRY_VERIFY(!window.busy());
        QCOMPARE(window.captureCounters().queueDropped, std::uint64_t(0));
        i18n::language().set("en");
        QCOMPARE(window.findChild<QLabel *>("captureStatus")->text(), QString("Stopped"));
    }
    void languageCatalogAndFileDialog() {
        QFile file(":/i18n/messages.json");
        QVERIFY(file.open(QIODevice::ReadOnly));
        const auto rows = QJsonDocument::fromJson(file.readAll()).array();
        QVERIFY(rows.size() > 360);
        for (const auto &code : {"en", "zh_TW"}) {
            QVERIFY(i18n::language().set(code));
            for (const auto &value : rows) {
                const auto row = value.toArray();
                QCOMPARE(i18n::text(row[0].toString()),
                         row[code == QString("en") ? 1 : 2].toString());
            }
        }
        i18n::language().set("en");
        const QRegularExpression han("[\\x{4e00}-\\x{9fff}]");
        auto translated = [&](const std::string &source) {
            const auto original = QString::fromStdString(source);
            QVERIFY2(!i18n::text(original).contains(han), original.toUtf8().constData());
        };
        for (const auto &samples :
             {fixtures::samples(), fixtures::ipv6Samples(), fixtures::analysisSamples(),
              fixtures::tcpConversationSamples(), fixtures::tcpStreamSamples()})
            for (const auto &raw : samples) {
                const auto packet = decodePacket(raw);
                translated(packet.protocol);
                translated(packet.summary);
                translated(packet.error);
                for (const auto &warning : packet.warnings)
                    translated(warning);
                std::vector<const Field *> pending;
                for (const auto &field : packet.fields)
                    pending.push_back(&field);
                while (!pending.empty()) {
                    const auto *field = pending.back();
                    pending.pop_back();
                    translated(field->name);
                    translated(field->value);
                    for (const auto &child : field->children)
                        pending.push_back(&child);
                }
            }
        for (const auto &code : {"en", "zh_CN", "zh_TW"}) {
            i18n::language().set(code);
            QFileDialog dialog;
            dialog.setOption(QFileDialog::DontUseNativeDialog);
            dialog.setAcceptMode(QFileDialog::AcceptOpen);
            dialog.show();
            QTest::qWait(5);
            QStringList labels;
            for (auto *label : dialog.findChildren<QLabel *>())
                labels << label->text();
            QVERIFY(labels.contains(
                code == QString("en")
                    ? QString("File &name:")
                    : (code == QString("zh_CN") ? QString("文件名:") : QString("檔案名稱:"))));
        }
    }
    void languageLayoutsAndExport() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        QTemporaryDir dir;
        std::vector<Packet> packets;
        for (auto raw : fixtures::ipv6Samples())
            packets.push_back(decodeSummary(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        auto *protocol = window.findChild<QComboBox *>("protocolFilter");
        protocol->setCurrentText("ICMP");
        window.findChild<QLineEdit *>("ipInput")->setText("2001:db8:1234:5678:abcd:ef01:2345:6789");
        window.findChild<QPushButton *>("applyFilterButton")->click();
        for (const auto &code : {"en", "zh_CN", "zh_TW"}) {
            i18n::language().set(code);
            for (bool dark : {false, true})
                for (const auto size : {QSize(1024, 768), QSize(1440, 900)}) {
                    window.setDarkTheme(dark);
                    window.resize(size);
                    QTest::qWait(10);
                    QCOMPARE(window.size(), size);
                    for (const auto &name :
                         {"startButton", "stopButton", "openButton", "saveButton", "moreButton",
                          "addressFilterToggle", "statisticsToggle", "followLatest"}) {
                        auto *control = window.findChild<QWidget *>(name);
                        QVERIFY(window.rect().contains(
                            QRect(control->mapTo(&window, QPoint{}), control->size())));
                    }
                    const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
                    if (!screenshots.isEmpty()) {
                        QDir().mkpath(screenshots);
                        QVERIFY(window.grab().save(screenshots + QString("/language-%1-%2-%3.png")
                                                                     .arg(code)
                                                                     .arg(dark ? "dark" : "light")
                                                                     .arg(size.width())));
                    }
                }
        }
        QSignalSpy saved(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(dir.filePath("原始 保存.pcap")));
        QTRY_COMPARE(saved.count(), 1);
        QVERIFY(saved[0][0].toBool());
        i18n::language().set("en");
        QCOMPARE(window.findChild<QLabel *>("exportProgress")->text(),
                 QString("Saved packets: 21"));
        PcapReader reader(std::filesystem::path(dir.filePath("原始 保存.pcap").toStdWString()));
        for (const auto &raw : fixtures::ipv6Samples()) {
            auto actual = reader.next();
            QVERIFY(actual);
            QVERIFY(actual->bytes == raw.bytes);
        }
        QVERIFY(!reader.next());
    }
    void streamBytesAndMarks() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        ingestStream(window);
        auto *dialog = startStream(window);
        auto *pane = dialog->findChild<StreamPane *>();
        QTRY_VERIFY(pane->ready());
        QCOMPARE(pane->findChild<QLabel *>("streamMetric1")->text(), QString("13"));
        QCOMPARE(pane->findChild<QLabel *>("streamMetric2")->text(), QString("0"));
        QCOMPARE(pane->findChild<QLabel *>("streamMetric3")->text(), QString("2"));
        QCOMPARE(pane->findChild<QLabel *>("streamMetric4")->text(), QString("1"));
        QCOMPARE(pane->findChild<QLabel *>("streamMetric5")->text(), QString("2"));
        QVERIFY(pane->findChild<QPlainTextEdit *>("streamBytes")
                    ->toPlainText()
                    .contains("HELLO WORLD !"));
        auto *ranges = pane->findChild<QTableView *>("streamRanges");
        auto *events = pane->findChild<QTableView *>("streamEvents");
        QAbstractItemModelTester tester(ranges->model(),
                                        QAbstractItemModelTester::FailureReportingMode::QtTest);
        QAbstractItemModelTester eventTester(
            events->model(), QAbstractItemModelTester::FailureReportingMode::QtTest);
        pane->findChild<QComboBox *>("streamDirection")->setCurrentIndex(1);
        QVERIFY(pane->findChild<QPlainTextEdit *>("streamBytes")->toPlainText().contains("OK"));
        QCOMPARE(pane->findChild<QLabel *>("streamMetric1")->text(), QString("2"));
        QModelIndex conflict;
        for (int row = 0; row < events->model()->rowCount(); ++row)
            if (events->model()->index(row, 2).data().toString() == "数据冲突")
                conflict = events->model()->index(row, 5);
        QVERIFY(conflict.isValid());
        QCOMPARE(conflict.data().toULongLong(), qulonglong(6));
        emit events->doubleClicked(conflict);
        QTRY_VERIFY(!window.findChild<TcpDialog *>());
        QVERIFY(waitForDetails(window));
        QCOMPARE(window.findChild<QLabel *>("detailPacketId")->text(), QString("#6"));
    }
    void streamGapsAndPaging() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw :
             {fixtures::tcp(2, 99),
              fixtures::tcp(24, 100, 0, false, 50000, false, std::vector<std::uint8_t>(2300, 'a')),
              fixtures::tcp(24, 2400, 0, false, 50000, false, std::vector<std::uint8_t>(2300, 'b')),
              fixtures::tcp(24, 4800, 0, false, 50000, false, {'z'})})
            packets.push_back(decodeSummary(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        auto *dialog = startStream(window);
        auto *pane = dialog->findChild<StreamPane *>();
        QTRY_VERIFY(pane->ready());
        auto *ranges = pane->findChild<QTableView *>("streamRanges");
        QCOMPARE(ranges->model()->rowCount(), 4);
        ranges->setCurrentIndex(ranges->model()->index(1, 0));
        QCOMPARE(pane->findChild<QLabel *>("streamPage")->text(), QString("3 / 5"));
        QVERIFY(pane->findChild<QPlainTextEdit *>("streamBytes")->toPlainText().contains("62 62"));
        ranges->setCurrentIndex(ranges->model()->index(2, 0));
        QVERIFY(pane->findChild<QPlainTextEdit *>("streamBytes")->toPlainText().isEmpty());
        QVERIFY(!pane->findChild<QPushButton *>("streamLocate")->isEnabled());
        ranges->setCurrentIndex(ranges->model()->index(3, 0));
        QVERIFY(pane->findChild<QPlainTextEdit *>("streamBytes")->toPlainText().contains("7a"));
        QCOMPARE(pane->findChild<QLabel *>("streamPage")->text(), QString("1 / 1"));
    }
    void streamLatestSnapshotAndEviction() {
        auto gate = std::make_shared<Gate>();
        auto calls = std::make_shared<std::atomic<int>>(0);
        auto options = testOptions();
        options.streamDecoder = [gate, calls](const TcpStreamRequest &request,
                                              std::stop_token stop) {
            if (++*calls == 1)
                gate->wait();
            return reassembleTcp(request, stop);
        };
        MainWindow window(nullptr, options);
        ReleaseGate release{gate};
        QVERIFY(waitForInterfaces(window));
        window.show();
        ingestStream(window);
        auto first = std::weak_ptr<const Packet>(window.packetModel()->packetAt(0));
        std::vector<Packet> second = {
            decodeSummary(fixtures::tcp(24, 1, 1, false, 51000, false, {'x'}))};
        window.ingestBenchmark(std::move(second));
        auto *dialog = startStream(window);
        auto *pane = dialog->findChild<StreamPane *>();
        QTRY_VERIFY(gate->entered.load());
        dialog->selectConversation(2);
        pane->start();
        dialog->selectConversation(1);
        pane->start();
        std::vector<Packet> more;
        for (int i = 0; i < 10001; ++i)
            more.push_back(decodeSummary(fixtures::icmp()));
        window.ingestBenchmark(std::move(more));
        QVERIFY(!first.expired());
        gate->release();
        QTRY_VERIFY(pane->ready());
        QCOMPARE(calls->load(), 2);
        QTRY_VERIFY(first.expired());
        QVERIFY(pane->findChild<QPlainTextEdit *>("streamBytes")
                    ->toPlainText()
                    .contains("HELLO WORLD !"));
    }
    void streamExitWaitsAndEscapeCancels() {
        for (bool mainExit : {false, true}) {
            auto gate = std::make_shared<Gate>();
            auto cancelled = std::make_shared<std::atomic<bool>>(false);
            auto options = testOptions();
            options.streamDecoder = [gate, cancelled](const TcpStreamRequest &request,
                                                      std::stop_token stop) {
                std::stop_callback notify(stop, [cancelled] { *cancelled = true; });
                gate->wait();
                return reassembleTcp(request, stop);
            };
            MainWindow window(nullptr, options);
            ReleaseGate release{gate};
            QVERIFY(waitForInterfaces(window));
            window.show();
            ingestStream(window);
            QPointer<TcpDialog> dialog = startStream(window);
            QTRY_VERIFY(gate->entered.load());
            int beats = 0;
            QTimer timer;
            timer.setTimerType(Qt::PreciseTimer);
            connect(&timer, &QTimer::timeout, this, [&] { ++beats; });
            timer.start(5);
            QTRY_VERIFY_WITH_TIMEOUT(beats >= 5, 250);
            if (mainExit)
                QVERIFY(!window.close());
            else
                QTest::keyClick(dialog, Qt::Key_Escape);
            QVERIFY(window.isVisible());
            QVERIFY(dialog);
            QVERIFY(cancelled->load());
            gate->release();
            QTRY_VERIFY(!dialog);
            if (mainExit)
                QTRY_VERIFY(!window.isVisible());
            else
                QVERIFY(window.isVisible());
        }
    }
    void streamFailureAndRetry() {
        auto calls = std::make_shared<std::atomic<int>>(0);
        auto options = testOptions();
        options.streamDecoder = [calls](const TcpStreamRequest &request, std::stop_token stop) {
            if (++*calls == 1)
                throw std::runtime_error("test failure");
            return reassembleTcp(request, stop);
        };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        window.show();
        ingestStream(window);
        auto *dialog = startStream(window);
        auto *pane = dialog->findChild<StreamPane *>();
        QTRY_COMPARE(pane->findChild<QLabel *>("streamPhase")->text(), QString("test failure"));
        QVERIFY(window.isVisible());
        pane->start();
        QTRY_VERIFY(pane->ready());
        pane->cancel();
        QVERIFY(!pane->ready());
        QCOMPARE(pane->findChild<QLabel *>("streamPhase")->text(), QString("已取消"));
    }
    void streamSelectionEvictionAndLayouts() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        ingestStream(window);
        auto *dialog = startStream(window);
        auto *pane = dialog->findChild<StreamPane *>();
        QTRY_VERIFY(pane->ready());
        for (bool dark : {false, true})
            for (const auto size : {QSize(1024, 640), QSize(1440, 800)}) {
                window.setDarkTheme(dark);
                dialog->resize(size);
                QTest::qWait(10);
                QVERIFY(dialog->findChild<QPushButton *>("streamNext")->isVisible());
                const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
                if (!screenshots.isEmpty()) {
                    QDir().mkpath(screenshots);
                    QVERIFY(dialog->grab().save(screenshots + QString("/stream-%1-%2.png")
                                                                  .arg(dark ? "dark" : "light")
                                                                  .arg(size.width())));
                }
            }
        std::vector<Packet> more;
        for (unsigned i = 0; i < 1025; ++i)
            more.push_back(decodeSummary(
                fixtures::tcp(2, 100, 0, false, static_cast<std::uint16_t>(1000 + i))));
        window.ingestBenchmark(std::move(more));
        auto *table = dialog->findChild<QTableView *>("tcpTable");
        QTRY_VERIFY_WITH_TIMEOUT(!table->currentIndex().isValid(), 2500);
        QTest::qWait(1100);
        QVERIFY(!table->currentIndex().isValid());
        QVERIFY(!pane->ready());
    }
    void tcpSummariesAndFilter() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::tcpConversationSamples())
            packets.push_back(decodeSummary(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        window.findChild<QLineEdit *>("ipInput")->setText("invalid draft");
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
        auto *dialog = window.findChild<TcpDialog *>();
        QVERIFY(dialog);
        auto *table = dialog->findChild<QTableView *>("tcpTable");
        QAbstractItemModelTester tester(table->model(),
                                        QAbstractItemModelTester::FailureReportingMode::QtTest);
        QCOMPARE(table->model()->rowCount(), 4);
        QCOMPARE(table->model()->index(0, 5).data().toString(), QString("FIN 已确认"));
        QCOMPARE(table->model()->index(0, 10).data().toDouble(), 30.0);
        QCOMPARE(dialog->findChild<QLabel *>("tcpMetric2")->text(), QString("1"));
        QCOMPARE(dialog->findChild<QLabel *>("tcpMode")->text(), QString("文件"));
        dialog->selectConversation(2);
        QCOMPARE(table->currentIndex().data(Qt::UserRole).toULongLong(), qulonglong(2));
        QCOMPARE(dialog->findChild<QLabel *>("tcpMetric3")->text(), QString("1"));
        dialog->selectConversation(1);
        dialog->findChild<QPushButton *>("tcpFilterButton")->click();
        QTRY_VERIFY(!window.findChild<TcpDialog *>());
        QCOMPARE(window.packetModel()->rowCount(), 10);
        QCOMPARE(window.packetModel()->filter().tcpConversationId, std::optional<std::uint64_t>(1));
        QCOMPARE(window.findChild<QLineEdit *>("ipInput")->text(), QString("invalid draft"));
        QVERIFY(window.findChild<QPushButton *>("tcpConversationCondition")->isVisible());
        window.findChild<QPushButton *>("tcpConversationCondition")->click();
        QCOMPARE(window.packetModel()->rowCount(), 15);
        QVERIFY(!window.packetModel()->filter().tcpConversationId);
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
        dialog = window.findChild<TcpDialog *>();
        dialog->selectConversation(1);
        dialog->findChild<QPushButton *>("tcpFilterButton")->click();
        QTRY_VERIFY(!window.findChild<TcpDialog *>());
        auto *protocol = window.findChild<QComboBox *>("protocolFilter");
        protocol->setCurrentText("ICMP");
        QVERIFY(!window.packetModel()->filter().tcpConversationId);
        QCOMPARE(window.packetModel()->rowCount(), 0);
    }
    void tcpEventNavigationAndEviction() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::tcpConversationSamples())
            packets.push_back(decodeSummary(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
        auto *dialog = window.findChild<TcpDialog *>();
        dialog->selectConversation(1);
        auto *events = dialog->findChild<QTreeWidget *>("tcpEvents");
        QTreeWidgetItem *handshake = nullptr;
        for (int i = 0; i < events->topLevelItemCount(); ++i)
            if (events->topLevelItem(i)->text(3) == "握手完成")
                handshake = events->topLevelItem(i);
        QVERIFY(handshake);
        events->setCurrentItem(handshake);
        dialog->findChild<QPushButton *>("tcpLocateButton")->click();
        QTRY_VERIFY(!window.findChild<TcpDialog *>());
        QVERIFY(waitForDetails(window));
        QCOMPARE(window.findChild<QLabel *>("detailPacketId")->text(), QString("#4"));
        window.findChild<QComboBox *>("protocolFilter")->setCurrentText("ICMP");
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
        dialog = window.findChild<TcpDialog *>();
        dialog->selectConversation(1);
        dialog->findChild<QPushButton *>("tcpLocateButton")->click();
        QCOMPARE(dialog->findChild<QLabel *>("tcpError")->text(), QString("报文已被筛选"));
        std::vector<Packet> more;
        for (int i = 0; i < 10001; ++i)
            more.push_back(decodeSummary(fixtures::icmp()));
        window.ingestBenchmark(std::move(more));
        dialog->findChild<QPushButton *>("tcpLocateButton")->click();
        QCOMPARE(dialog->findChild<QLabel *>("tcpError")->text(), QString("报文已覆盖"));
        QCOMPARE(dialog->findChild<QLabel *>("tcpCount")->text(), QString("4"));
        dialog->findChild<QPushButton *>("tcpFilterButton")->click();
        QCOMPARE(dialog->findChild<QLabel *>("tcpError")->text(), QString("无匹配报文"));
        QVERIFY(!window.packetModel()->filter().tcpConversationId);
        QPointer<TcpDialog> tracked = dialog;
        window.close();
        QTRY_VERIFY(!tracked);
        QVERIFY(!window.isVisible());
    }
    void tcpLiveFileIsolationAndSettings() {
        auto options = testOptions();
        options.capture.run = [](const QString &, bool, std::stop_token stop,
                                 const CaptureHooks::Sink &sink, const CaptureHooks::Opened &opened,
                                 const LiveCaptureOptions &) {
            opened("捕获中");
            for (auto raw : fixtures::tcpConversationSamples())
                sink(std::move(raw));
            while (!stop.stop_requested())
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
        };
        {
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            window.show();
            window.findChild<QComboBox *>("protocolFilter")->setCurrentText("ICMP");
            window.findChild<QPushButton *>("startButton")->click();
            QTRY_COMPARE(window.sessionStats().received, std::uint64_t(15));
            QCOMPARE(window.packetModel()->rowCount(), 0);
            window.findChild<QAction *>("tcpConversationsAction")->trigger();
            auto *dialog = window.findChild<TcpDialog *>();
            QCOMPARE(dialog->findChild<QLabel *>("tcpCount")->text(), QString("4"));
            QCOMPARE(dialog->findChild<QLabel *>("tcpMode")->text(), QString("实时"));
            window.stopCapture();
            QTRY_VERIFY(!window.busy());
            window.findChild<QTabBar *>("sessionTabs")->setCurrentIndex(1);
            QCOMPARE(dialog->findChild<QTableView *>("tcpTable")->model()->rowCount(), 0);
            std::vector<Packet> packets;
            for (auto raw : fixtures::tcpConversationSamples())
                packets.push_back(decodeSummary(std::move(raw)));
            window.ingestBenchmark(std::move(packets));
            QTRY_COMPARE_WITH_TIMEOUT(
                dialog->findChild<QTableView *>("tcpTable")->model()->rowCount(), 4, 2000);
            dialog->selectConversation(2);
            dialog->findChild<QPushButton *>("tcpFilterButton")->click();
            QTRY_VERIFY(!window.findChild<TcpDialog *>());
            QCOMPARE(window.packetModel()->rowCount(), 2);
            QVERIFY(window.packetModel()->filter().tcpConversationId);
            window.findChild<QTabBar *>("sessionTabs")->setCurrentIndex(0);
            QVERIFY(!window.packetModel()->filter().tcpConversationId);
            QCOMPARE(window.packetModel()->rowCount(), 15);
        }
        MainWindow restored(nullptr, options);
        QVERIFY(waitForInterfaces(restored));
        QCOMPARE(restored.packetModel()->filter().protocol, std::string("TCP"));
        QVERIFY(!restored.packetModel()->filter().tcpConversationId);
    }
    void tcpThemesAndSizes() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::tcpConversationSamples())
            packets.push_back(decodeSummary(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
        auto *dialog = window.findChild<TcpDialog *>();
        for (bool dark : {false, true})
            for (const auto size : {QSize(1024, 640), QSize(1440, 800)}) {
                window.setDarkTheme(dark);
                dialog->resize(size);
                dialog->selectConversation(2);
                QTest::qWait(10);
                auto *table = dialog->findChild<QTableView *>("tcpTable");
                QVERIFY(table->width() <= dialog->width());
                QCOMPARE(table->model()->index(1, 1).data(Qt::ToolTipRole).toString(),
                         QString("2001:db8::1"));
                for (const auto &name : {"tcpFilterButton", "tcpLocateButton"}) {
                    auto *button = dialog->findChild<QPushButton *>(name);
                    QVERIFY(dialog->rect().contains(
                        QRect(button->mapTo(dialog, QPoint{}), button->size())));
                }
                const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
                if (!screenshots.isEmpty()) {
                    QDir().mkpath(screenshots);
                    QVERIFY(dialog->grab().save(
                        screenshots +
                        QString("/tcp-%1-%2.png").arg(dark ? "dark" : "light").arg(size.width())));
                }
            }
    }
    void tcpPcapReopenAndStaleRequests() {
        QTemporaryDir directory;
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::tcpConversationSamples())
            packets.push_back(decodeSummary(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
        auto *dialog = window.findChild<TcpDialog *>();
        dialog->selectConversation(1);
        const SessionStore *oldStore = nullptr;
        quint64 oldGeneration = 0;
        connect(dialog, &TcpDialog::filterRequested, this,
                [&](quint64, quint64 generation, const SessionStore *store) {
                    oldStore = store;
                    oldGeneration = generation;
                });
        dialog->findChild<QPushButton *>("tcpFilterButton")->click();
        QTRY_VERIFY(!window.findChild<TcpDialog *>());
        QVERIFY(oldStore);
        QCOMPARE(window.packetModel()->rowCount(), 10);
        const auto path = directory.filePath("tcp.pcap");
        QSignalSpy saved(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(path));
        QTRY_COMPARE(saved.count(), 1);
        QCOMPARE(saved.front()[2].toULongLong(), qulonglong(15));
        QSignalSpy opened(&window, &MainWindow::fileOpenFinished);
        QVERIFY(window.openFile(path));
        QTRY_COMPARE(opened.count(), 1);
        QVERIFY(!window.packetModel()->filter().tcpConversationId);
        QCOMPARE(window.packetModel()->rowCount(), 15);
        QCOMPARE(window.tcpConversations().items().size(), std::size_t(4));
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
        dialog = window.findChild<TcpDialog *>();
        const auto before = window.findChild<QTableView *>("packetTable")->currentIndex();
        emit dialog->filterRequested(1, oldGeneration, oldStore);
        emit dialog->locateRequested(1, oldGeneration, oldStore);
        QVERIFY(!window.packetModel()->filter().tcpConversationId);
        QCOMPARE(window.findChild<QTableView *>("packetTable")->currentIndex(), before);
        QCOMPARE(
            dialog->findChild<QTableView *>("tcpTable")->model()->index(0, 10).data().toDouble(),
            30.0);
    }
    void bpfStartIsTransactional() {
        auto options = testOptions();
        options.capture = fakeCapture();
        auto base = options.capture.run;
        options.capture.run = [base](const QString &target, bool file, std::stop_token stop,
                                     const CaptureHooks::Sink &sink,
                                     const CaptureHooks::Opened &opened,
                                     const LiveCaptureOptions &capture) {
            if (capture.bpf == "bad (")
                throw std::runtime_error("捕获过滤无效: syntax");
            if (capture.bpf == "install-failure")
                throw std::runtime_error("捕获过滤安装失败: test");
            if (capture.bpf != "icmp")
                throw std::runtime_error("Unexpected BPF");
            base(target, file, stop, sink, opened, capture);
        };
        {
            QSettings saved(options.settingsFile, QSettings::IniFormat);
            saved.setValue("capture/bpf", "icmp");
        }
        {
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            window.show();
            auto *start = window.findChild<QPushButton *>("startButton");
            start->click();
            QTRY_VERIFY(window.sessionStats().received > 0);
            window.findChild<QAction *>("captureFilterAction")->trigger();
            QVERIFY(window.findChild<QLineEdit *>("bpfInput")->isReadOnly());
            window.findChild<QDialog *>("captureFilterDialog")->close();
            QTest::qWait(1);
            window.stopCapture();
            QTRY_VERIFY(!window.busy());
            QVERIFY(waitForDetails(window));
            const auto retained = window.packetModel()->rowCount();
            const auto first = window.packetModel()->packetAt(0);
            QVERIFY(retained > 0);
            QCOMPARE(window.findChild<QLabel *>("bpfMarker")->toolTip(), QString("icmp"));
            window.findChild<QComboBox *>("protocolFilter")->setCurrentText("ICMP");
            for (const auto &expression : {QString("bad ("), QString("install-failure")}) {
                QVERIFY(setBpf(window, expression));
                start->click();
                QTRY_VERIFY(!window.busy());
                QCOMPARE(window.packetModel()->rowCount(), retained);
                QCOMPARE(window.packetModel()->packetAt(0), first);
                QCOMPARE(window.packetModel()->filter().protocol, std::string("ICMP"));
                QVERIFY(window.findChild<QLabel *>("captureStatus")->text().startsWith("捕获过滤"));
            }
        }
        QSettings saved(options.settingsFile, QSettings::IniFormat);
        QCOMPARE(saved.value("capture/bpf").toString(), QString("icmp"));
        MainWindow restored(nullptr, options);
        QVERIFY(waitForInterfaces(restored));
        QVERIFY(!restored.busy());
        restored.findChild<QAction *>("captureFilterAction")->trigger();
        QCOMPARE(restored.findChild<QLineEdit *>("bpfInput")->text(), QString("icmp"));
    }
    void bpfCancelledStartKeepsCache() {
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.capture = fakeCapture();
        auto source = options.capture.run;
        auto delay = std::make_shared<std::atomic<bool>>(false);
        options.capture.run = [gate, delay, source](const QString &target, bool file,
                                                    std::stop_token stop,
                                                    const CaptureHooks::Sink &sink,
                                                    const CaptureHooks::Opened &opened,
                                                    const LiveCaptureOptions &capture) {
            if (*delay)
                gate->wait();
            if (stop.stop_requested())
                return;
            source(target, file, stop, sink, opened, capture);
        };
        MainWindow window(nullptr, options);
        ReleaseGate release{gate};
        QVERIFY(waitForInterfaces(window));
        window.show();
        auto *start = window.findChild<QPushButton *>("startButton");
        start->click();
        QTRY_VERIFY(window.sessionStats().received > 0);
        window.stopCapture();
        QTRY_VERIFY(!window.busy());
        const auto count = window.packetModel()->rowCount();
        const auto first = window.packetModel()->packetAt(0);
        *delay = true;
        QVERIFY(setBpf(window, "tcp"));
        start->click();
        QTRY_VERIFY(gate->entered.load());
        window.stopCapture();
        QCOMPARE(window.captureState(), MainWindow::CaptureState::Stopping);
        gate->release();
        QTRY_VERIFY(!window.busy());
        QCOMPARE(window.packetModel()->rowCount(), count);
        QCOMPARE(window.packetModel()->packetAt(0), first);
    }
    void asynchronousDetailsKeepLatestSelection() {
        auto gate = std::make_shared<Gate>();
        auto calls = std::make_shared<std::atomic<int>>(0);
        auto options = testOptions();
        options.detailDecoder = [gate, calls](const RawPacket &raw, std::stop_token) {
            if (++*calls == 1)
                gate->wait();
            return decodeDetails(raw);
        };
        MainWindow window(nullptr, options);
        ReleaseGate release{gate};
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        packets.push_back(decodeSummary(fixtures::icmp()));
        packets.push_back(decodeSummary(fixtures::icmp(0)));
        window.ingestBenchmark(std::move(packets));
        window.selectPacket(0);
        QTRY_VERIFY(gate->entered.load());
        int beats = 0;
        QTimer heartbeat;
        connect(&heartbeat, &QTimer::timeout, this, [&] { ++beats; });
        heartbeat.setTimerType(Qt::PreciseTimer);
        heartbeat.start(5);
        QTRY_VERIFY_WITH_TIMEOUT(beats >= 3, 250);
        for (int i = 0; i < 100; ++i)
            window.selectPacket(i % 2);
        gate->release();
        QVERIFY(waitForDetails(window));
        QCOMPARE(calls->load(), 2);
        QCOMPARE(window.findChild<QLabel *>("detailPacketId")->text(), QString("#2"));
        auto *tree = window.findChild<QTreeWidget *>("fieldTree");
        QCOMPARE(tree->topLevelItemCount(), 3);
        QVERIFY(tree->topLevelItem(2)->child(0)->text(1).startsWith("0 "));
        std::vector<Packet> evict;
        for (int i = 0; i < 10001; ++i)
            evict.push_back(decodeSummary(fixtures::icmp()));
        window.ingestBenchmark(std::move(evict));
        window.selectPacket(0);
        QVERIFY(waitForDetails(window));
        QVERIFY(window.findChild<QLabel *>("detailPacketId")->text() != "#2");
    }
    void closeWaitsForDetails() {
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.detailDecoder = [gate](const RawPacket &raw, std::stop_token) {
            gate->wait();
            return decodeDetails(raw);
        };
        MainWindow window(nullptr, options);
        ReleaseGate release{gate};
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        packets.push_back(decodeSummary(fixtures::icmp()));
        window.ingestBenchmark(std::move(packets));
        window.selectPacket(0);
        QTRY_VERIFY(gate->entered.load());
        QVERIFY(!window.close());
        QVERIFY(window.isVisible());
        gate->release();
        QTRY_VERIFY(!window.isVisible());
    }
    void initTestCase() {
        const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
        if (!screenshots.isEmpty())
            QVERIFY(QDir().mkpath(screenshots));
        qApp->setStyle(QStyleFactory::create("Fusion"));
        qApp->setApplicationVersion(ETHERSCOPE_VERSION);
        if (QGuiApplication::platformName() == "offscreen") {
            const auto fonts = qEnvironmentVariable("WINDIR") + "/Fonts/";
            QVERIFY(QFontDatabase::addApplicationFont(fonts + "msyh.ttc") >= 0);
            QVERIFY(QFontDatabase::addApplicationFont(fonts + "consola.ttf") >= 0);
            QVERIFY(QFontDatabase::addApplicationFont(fonts + "segoeui.ttf") >= 0);
        }
        qApp->setFont(QFont("Microsoft YaHei UI", 10));
        qApp->setQuitOnLastWindowClosed(false);
    }
    void importFilterInspectAndSave() {
        QTemporaryDir temp;
        QVERIFY(temp.isValid());
        const auto input = temp.filePath("input.pcap"), output = temp.filePath("output.pcap");
        std::vector<Packet> packets;
        for (auto r : fixtures::samples())
            packets.push_back(decodePacket(std::move(r)));
        {
            std::vector<const Packet *> refs;
            for (const auto &p : packets)
                refs.push_back(&p);
            std::ofstream out(std::filesystem::path(input.toStdWString()), std::ios::binary);
            writePcap(out, refs);
        }
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        QVERIFY(window.openFile(input));
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 5000);
        QTRY_COMPARE_WITH_TIMEOUT(window.packetModel()->rowCount(), 12, 5000);
        auto *ip = window.findChild<QLineEdit *>("ipInput");
        auto *apply = window.findChild<QPushButton *>("applyFilterButton");
        auto *filterStatus = window.findChild<QLabel *>("ipError");
        QVERIFY(ip && apply && filterStatus);
        window.findChild<QPushButton *>("addressFilterToggle")->setChecked(true);
        ip->setText("192.0.2.1");
        apply->click();
        QCOMPARE(window.packetModel()->rowCount(), 10);
        ip->setText("999.0.0.1");
        apply->click();
        QCOMPARE(window.packetModel()->rowCount(), 10);
        QCOMPARE(filterStatus->text(), QString("IPv4 地址无效"));
        window.findChild<QPushButton *>("clearFilterButton")->click();
        QCOMPARE(window.packetModel()->rowCount(), 12);
        window.selectPacket(0);
        QVERIFY(waitForDetails(window));
        auto *tree = window.findChild<QTreeWidget *>("fieldTree");
        QVERIFY(tree && tree->topLevelItemCount() == 3);
        auto *ipGroup = tree->topLevelItem(1);
        QVERIFY(ipGroup->text(0) == "IPv4");
        tree->setCurrentItem(ipGroup->child(0));
        auto *hex = window.findChild<QPlainTextEdit *>("hexView");
        QVERIFY(!hex->extraSelections().empty());
        QCOMPARE(hex->extraSelections().front().cursor.selectedText(), QString("45"));
        QSignalSpy savedResult(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(output));
        QTRY_COMPARE_WITH_TIMEOUT(savedResult.count(), 1, 5000);
        QVERIFY(savedResult.front()[0].toBool());
        PcapReader saved(std::filesystem::path(output.toStdWString()));
        int n = 0;
        while (saved.next())
            ++n;
        QCOMPARE(n, 12);
        auto *tabs = window.findChild<QTabBar *>("sessionTabs");
        tabs->setCurrentIndex(0);
        QCOMPARE(window.packetModel()->rowCount(), 0);
        QCOMPARE(tree->topLevelItemCount(), 0);
        QVERIFY(hex->toPlainText().isEmpty());
        tabs->setCurrentIndex(1);
        QCOMPARE(window.packetModel()->rowCount(), 12);
        ip->setText("192.0.2.200");
        apply->click();
        QCOMPARE(window.packetModel()->rowCount(), 0);
        window.findChild<QPushButton *>("clearFilterButton")->click();
        const auto screenshotDir = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
        if (!screenshotDir.isEmpty()) {
            QDir().mkpath(screenshotDir);
            window.findChild<QPushButton *>("addressFilterToggle")->setChecked(false);
            window.selectPacket(2);
            QVERIFY(waitForDetails(window));
            window.resize(1440, 900);
            window.setDarkTheme(false);
            QTest::qWait(100);
            QVERIFY(window.grab().save(screenshotDir + "/light.png"));
            window.setDarkTheme(true);
            QTest::qWait(100);
            QVERIFY(window.grab().save(screenshotDir + "/dark.png"));
            window.resize(1024, 768);
            QTest::qWait(100);
            QVERIFY(window.grab().save(screenshotDir + "/compact.png"));
        }
    }
    void errorsAndRepeatedStop() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        QVERIFY(window.openFile("missing-file.pcap"));
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 3000);
        QVERIFY(window.findChild<QLabel *>("captureStatus")->text().contains("无法打开"));
        QTest::qWait(250);
        QVERIFY(window.findChild<QLabel *>("captureStatus")->text().contains("无法打开"));
        CaptureEngine engine;
        QSignalSpy failed(&engine, &CaptureEngine::failed);
        QSignalSpy done(&engine, &CaptureEngine::finished);
        engine.startFile("missing-file.pcap");
        QTRY_COMPARE_WITH_TIMEOUT(failed.count(), 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 3000);
        QElapsedTimer timer;
        timer.start();
        engine.stop();
        engine.stop();
        QVERIFY(timer.elapsed() < 1000);
        QTemporaryDir dir;
        auto malformed = dir.filePath("bad.pcap");
        {
            QFile f(malformed);
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write("not pcap");
        }
        QVERIFY(window.openFile(malformed));
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 3000);
    }
    void ipv6ImportFilterInspectSaveAndRestore() {
        QTemporaryDir dir;
        auto options = testOptions();
        const auto input = dir.filePath("ipv6.pcap"), output = dir.filePath("saved-ipv6.pcap");
        auto raws = fixtures::ipv6Samples();
        raws.push_back(fixtures::icmp());
        std::vector<Packet> packets;
        int ipv6Count = 0, icmpv6Count = 0;
        for (auto raw : raws) {
            auto p = decodePacket(raw);
            if (p.sourceIpv6)
                ++ipv6Count;
            if (p.protocol == "ICMPv6")
                ++icmpv6Count;
            packets.push_back(std::move(p));
        }
        {
            std::vector<const Packet *> refs;
            for (const auto &p : packets)
                refs.push_back(&p);
            std::ofstream file(std::filesystem::path(input.toStdWString()), std::ios::binary);
            writePcap(file, refs);
        }
        {
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            window.show();
            QVERIFY(window.openFile(input));
            QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 5000);
            QCOMPARE(window.packetModel()->rowCount(), int(raws.size()));
            auto *ip = window.findChild<QLineEdit *>("ipInput");
            auto *protocol = window.findChild<QComboBox *>("protocolFilter");
            auto *apply = window.findChild<QPushButton *>("applyFilterButton");
            protocol->setCurrentText("IPv6");
            apply->click();
            QCOMPARE(window.packetModel()->rowCount(), ipv6Count);
            ip->setText("2001:0DB8:0000:0:0:0:0:1");
            apply->click();
            QCOMPARE(window.packetModel()->rowCount(), ipv6Count);
            window.selectPacket(0);
            QVERIFY(waitForDetails(window));
            auto *tree = window.findChild<QTreeWidget *>("fieldTree");
            auto *group = tree->topLevelItem(1);
            QCOMPARE(group->text(0), QString("IPv6"));
            QCOMPARE(group->child(8)->text(1), QString("2001:db8::1"));
            tree->setCurrentItem(group->child(8));
            auto *hex = window.findChild<QPlainTextEdit *>("hexView");
            QVERIFY(!hex->extraSelections().empty());
            QVERIFY(hex->extraSelections().front().cursor.selectedText().contains(
                "20 01 0d b8", Qt::CaseInsensitive));
            window.findChild<QComboBox *>("ipDirection")->setCurrentIndex(2);
            apply->click();
            QCOMPARE(window.packetModel()->rowCount(), 0);
            window.findChild<QComboBox *>("ipDirection")->setCurrentIndex(1);
            protocol->setCurrentText("ICMPv6");
            apply->click();
            QCOMPARE(window.packetModel()->rowCount(), icmpv6Count);
            ip->setText("2001:::1");
            apply->click();
            QCOMPARE(window.packetModel()->rowCount(), icmpv6Count);
            QVERIFY(window.packetModel()->filter().ipv6);
            QSignalSpy done(&window, &MainWindow::saveFinished);
            QVERIFY(window.saveFile(output));
            QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 5000);
            QVERIFY(done.front()[0].toBool());
            QCOMPARE(done.front()[2].toULongLong(), qulonglong(raws.size()));
            PcapReader reader(std::filesystem::path(output.toStdWString()));
            for (const auto &raw : raws) {
                auto saved = reader.next();
                QVERIFY(saved);
                QVERIFY(saved->bytes == raw.bytes);
            }
            QVERIFY(!reader.next());
            const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
            if (!screenshots.isEmpty()) {
                ip->setText("2001:db8::1");
                protocol->setCurrentText("IPv6");
                apply->click();
                window.selectPacket(11);
                QVERIFY(waitForDetails(window));
                window.resize(1440, 900);
                window.findChild<QSplitter *>("packetDetailSplitter")->setSizes({220, 360});
                tree->topLevelItem(0)->setExpanded(false);
                tree->setCurrentItem(tree->topLevelItem(1)->child(8));
                tree->scrollToItem(tree->topLevelItem(1));
                auto *table = window.findChild<QTableView *>("packetTable");
                table->scrollTo(table->currentIndex());
                QTest::qWait(100);
                QVERIFY(window.grab().save(screenshots + "/ipv6.png"));
                protocol->setCurrentText("ICMPv6");
                apply->click();
                ip->setText("invalid IPv6 draft");
            }
            QVERIFY(window.close());
        }
        MainWindow restored(nullptr, options);
        QVERIFY(waitForInterfaces(restored));
        QCOMPARE(restored.findChild<QLineEdit *>("ipInput")->text(), QString("2001:db8::1"));
        QCOMPARE(restored.findChild<QComboBox *>("protocolFilter")->currentText(),
                 QString("ICMPv6"));
        QVERIFY(restored.packetModel()->filter().ipv6);
        QVERIFY(restored.findChild<QPushButton *>("ipCondition")
                    ->toolTip()
                    .contains("IPv6 2001:db8::1"));
        QVERIFY(!restored.busy());
    }
    void incrementalRowsAndEviction() {
        const auto raw = fixtures::icmp();
        SessionStore store(4, raw.bytes.size() * 4);
        PacketModel model(&store);
        QAbstractItemModelTester tester(&model,
                                        QAbstractItemModelTester::FailureReportingMode::QtTest);
        QSignalSpy resets(&model, &QAbstractItemModel::modelReset);
        auto append = [&](int count) {
            std::vector<Packet> batch;
            while (count-- > 0)
                batch.push_back(decodePacket(raw));
            model.append(std::move(batch));
        };
        append(3);
        QPersistentModelIndex selected(model.index(1, 0));
        QCOMPARE(selected.data().toULongLong(), qulonglong(2));
        append(1);
        QCOMPARE(selected.row(), 1);
        append(1);
        QCOMPARE(selected.row(), 0);
        QCOMPARE(selected.data().toULongLong(), qulonglong(2));
        append(1);
        QVERIFY(!selected.isValid());
        QCOMPARE(model.packetAt(0)->id, std::uint64_t(3));
        QCOMPARE(resets.count(), 0);
        auto filter = parseFilter("", Direction::Either, "", Direction::Either, "UDP");
        model.setFilter(*filter.value);
        QCOMPARE(model.rowCount(), 0);
        resets.clear();
        // Exercise filtered insertions, batches larger than the cache, and eviction by raw-byte
        // size.
        for (int i = 0; i < 30; ++i) {
            std::vector<Packet> batch;
            for (int j = 0; j < i % 7 + 1; ++j)
                batch.push_back(decodePacket((i + j) % 2 ? fixtures::samples()[6] : raw));
            model.append(std::move(batch));
            int row = 0;
            for (const auto &packet : store.packets())
                if (model.filter().matches(*packet)) {
                    QCOMPARE(model.packetAt(row)->id, packet->id);
                    ++row;
                }
            QCOMPARE(model.rowCount(), row);
        }
        QCOMPARE(resets.count(), 0);
        SessionStore byteStore(100, raw.bytes.size() * 2);
        PacketModel byteModel(&byteStore);
        QAbstractItemModelTester byteTester(&byteModel,
                                            QAbstractItemModelTester::FailureReportingMode::QtTest);
        std::vector<Packet> batch;
        for (int i = 0; i < 5; ++i)
            batch.push_back(decodePacket(raw));
        byteModel.append(std::move(batch));
        QCOMPARE(byteModel.rowCount(), 2);
        QCOMPARE(byteModel.packetAt(0)->id, std::uint64_t(4));
        auto oversized = raw;
        oversized.bytes.resize(raw.bytes.size() * 3);
        oversized.originalLength = static_cast<std::uint32_t>(oversized.bytes.size());
        std::vector<Packet> rejected;
        rejected.push_back(decodePacket(std::move(oversized)));
        byteModel.append(std::move(rejected));
        QCOMPARE(byteModel.rowCount(), 2);
        QCOMPARE(byteModel.packetAt(0)->id, std::uint64_t(4));
    }
    void unchangedFilterKeepsPersistentRows() {
        SessionStore store;
        PacketModel model(&store);
        std::vector<Packet> packets;
        for (auto raw : fixtures::samples())
            packets.push_back(decodePacket(std::move(raw)));
        model.append(std::move(packets));
        const auto filter =
            *parseFilter("", Direction::Either, "", Direction::Either, "ICMP").value;
        model.setFilter(filter);
        QPersistentModelIndex selected(model.index(2, 0));
        const auto id = selected.data();
        QSignalSpy resets(&model, &QAbstractItemModel::modelReset);
        model.setFilter(*parseFilter("", Direction::Either, "", Direction::Either, " ICMP ").value);
        QCOMPARE(resets.count(), 0);
        QVERIFY(selected.isValid());
        QCOMPARE(selected.data(), id);
        model.setFilter(*parseFilter("", Direction::Either, "", Direction::Either, "UDP").value);
        QCOMPARE(resets.count(), 1);
        QVERIFY(!selected.isValid());
        QCOMPARE(model.rowCount(), 1);
    }
    void inspectionSurvivesIncomingPackets() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> first;
        first.push_back(decodePacket(fixtures::icmp()));
        window.ingestBenchmark(std::move(first));
        window.selectPacket(0);
        QVERIFY(waitForDetails(window));
        auto *tree = window.findChild<QTreeWidget *>("fieldTree");
        auto *hex = window.findChild<QPlainTextEdit *>("hexView");
        auto *item = tree->topLevelItem(1)->child(0);
        tree->setCurrentItem(item);
        tree->topLevelItem(0)->setExpanded(false);
        const auto text = hex->toPlainText();
        QSignalSpy resets(window.packetModel(), &QAbstractItemModel::modelReset);
        std::vector<Packet> more;
        for (int i = 0; i < 100; ++i)
            more.push_back(decodePacket(fixtures::icmp()));
        window.ingestBenchmark(std::move(more));
        QCOMPARE(resets.count(), 0);
        QCOMPARE(tree->currentItem(), item);
        QVERIFY(!tree->topLevelItem(0)->isExpanded());
        QCOMPARE(hex->toPlainText(), text);
        QCOMPARE(hex->extraSelections().front().cursor.selectedText(), QString("45"));
    }
    void largePacketPagingAndAtomicSave() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        auto raw = fixtures::icmp();
        raw.bytes.resize(16 * 1024 * 1024, 0x5a);
        raw.originalLength = static_cast<std::uint32_t>(raw.bytes.size());
        auto packet = decodePacket(raw);
        packet.fields.push_back({"尾字节", "5a", raw.bytes.size() - 1, 1, {}});
        std::vector<Packet> batch;
        batch.push_back(std::move(packet));
        window.ingestBenchmark(std::move(batch));
        window.selectPacket(0);
        QVERIFY(waitForDetails(window));
        auto *tree = window.findChild<QTreeWidget *>("fieldTree");
        auto *hex = window.findChild<QPlainTextEdit *>("hexView");
        auto *previous = window.findChild<QPushButton *>("previousBytesButton");
        auto *next = window.findChild<QPushButton *>("nextBytesButton");
        QVERIFY(hex->document()->blockCount() <= 257);
        QVERIFY(next->isVisible() && next->isEnabled());
        QVERIFY(!previous->isEnabled());
        QTest::mouseClick(next, Qt::LeftButton);
        QVERIFY(hex->toPlainText().startsWith("001000"));
        tree->setCurrentItem(tree->topLevelItem(tree->topLevelItemCount() - 1));
        QVERIFY(hex->toPlainText().startsWith("fff000"));
        QVERIFY(!next->isEnabled());
        QVERIFY(previous->isEnabled());
        QCOMPARE(hex->extraSelections().front().cursor.selectedText(), QString("5a"));
        QTest::mouseClick(previous, Qt::LeftButton);
        QVERIFY(hex->toPlainText().startsWith("ffe000"));
        QVERIFY(hex->extraSelections().isEmpty());
        const auto screenshotDir = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
        if (!screenshotDir.isEmpty()) {
            QTest::qWait(50);
            QVERIFY(window.grab().save(screenshotDir + "/large-packet.png"));
        }
        const auto path = dir.filePath("large.pcap");
        QSignalSpy savedResult(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(path));
        QTRY_COMPARE_WITH_TIMEOUT(savedResult.count(), 1, 5000);
        QVERIFY(savedResult.front()[0].toBool());
        {
            PcapReader reader(std::filesystem::path(path.toStdWString()));
            auto saved = reader.next();
            QVERIFY(saved && saved->bytes == raw.bytes);
            QVERIFY(!reader.next());
        }
        // A failed replacement leaves the previously saved file untouched.
        std::ifstream before(std::filesystem::path(path.toStdWString()), std::ios::binary);
        const std::string original((std::istreambuf_iterator<char>(before)), {});
        before.close();
        auto invalid = decodePacket(fixtures::icmp());
        invalid.raw.linkType = 113;
        std::vector<Packet> bad;
        bad.push_back(std::move(invalid));
        window.ingestBenchmark(std::move(bad));
        QVERIFY(window.saveFile(path));
        QTRY_COMPARE_WITH_TIMEOUT(savedResult.count(), 2, 5000);
        QVERIFY(!savedResult.back()[0].toBool());
        std::ifstream after(std::filesystem::path(path.toStdWString()), std::ios::binary);
        const std::string unchanged((std::istreambuf_iterator<char>(after)), {});
        QCOMPARE(unchanged, original);
        const auto message = window.findChild<QLabel *>("captureStatus")->text();
        QTest::qWait(250);
        QCOMPARE(window.findChild<QLabel *>("captureStatus")->text(), message);
    }
    void asyncSnapshotAndEviction() {
        QTemporaryDir dir;
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.exportWriter = gatedWriter(gate);
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.show();
        const auto originals = fixtures::samples();
        std::vector<Packet> batch;
        for (auto raw : originals)
            batch.push_back(decodePacket(std::move(raw)));
        window.ingestBenchmark(std::move(batch));
        std::weak_ptr<const Packet> first = window.packetModel()->packetAt(0);
        window.findChild<QLineEdit *>("ipInput")->setText("192.0.2.200");
        window.findChild<QPushButton *>("applyFilterButton")->click();
        QCOMPARE(window.packetModel()->rowCount(), 0);
        QSignalSpy done(&window, &MainWindow::saveFinished);
        const auto path = dir.filePath("snapshot.pcap");
        QVERIFY(window.saveFile(path));
        QVERIFY(!window.saveFile(dir.filePath("duplicate.pcap")));
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 3000);
        std::vector<Packet> more;
        for (int i = 0; i < 10050; ++i)
            more.push_back(decodePacket(fixtures::icmp()));
        window.ingestBenchmark(std::move(more));
        QVERIFY(!first.expired());
        window.findChild<QTabBar *>("sessionTabs")->setCurrentIndex(0);
        QCOMPARE(window.packetModel()->rowCount(), 0);
        int beats = 0;
        QTimer heartbeat;
        connect(&heartbeat, &QTimer::timeout, &window, [&] { ++beats; });
        heartbeat.setTimerType(Qt::PreciseTimer);
        heartbeat.start(20);
        QTRY_VERIFY_WITH_TIMEOUT(beats >= 3, 250);
        QVERIFY(window.saving());
        gate->release();
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 5000);
        QVERIFY(done.front()[0].toBool());
        QCOMPARE(done.front()[2].toULongLong(), qulonglong(12));
        QVERIFY(first.expired());
        PcapReader reader(std::filesystem::path(path.toStdWString()));
        for (const auto &raw : originals) {
            auto saved = reader.next();
            QVERIFY(saved && saved->bytes == raw.bytes && saved->timestampNs == raw.timestampNs);
        }
        QVERIFY(!reader.next());
        QVERIFY(!QFile::exists(dir.filePath("duplicate.pcap")));
    }
    void captureContinuesAndCloseWaitsForSave() {
        QTemporaryDir dir;
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.capture = fakeCapture();
        options.exportWriter = gatedWriter(gate);
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.show();
        QTest::mouseClick(window.findChild<QPushButton *>("startButton"), Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(window.packetModel()->rowCount() > 20, 3000);
        const int before = window.packetModel()->rowCount();
        QSignalSpy done(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(dir.filePath("capture.pcap")));
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 3000);
        QTRY_VERIFY_WITH_TIMEOUT(window.packetModel()->rowCount() > before + 20, 3000);
        QVERIFY(window.busy());
        auto *engine = window.findChild<CaptureEngine *>();
        QSignalSpy stopped(engine, &CaptureEngine::finished);
        QVERIFY(!window.close());
        QVERIFY(window.isVisible());
        QTRY_COMPARE_WITH_TIMEOUT(stopped.count(), 1, 3000);
        QVERIFY(window.isVisible());
        QVERIFY(window.saving());
        gate->release();
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 5000);
        QVERIFY(done.front()[0].toBool());
        QTRY_VERIFY_WITH_TIMEOUT(!window.isVisible(), 3000);
    }
    void saveFailureCancelsCloseAndPreservesTarget() {
        QTemporaryDir dir;
        const auto path = dir.filePath("existing.pcap");
        {
            QFile file(path);
            QVERIFY(file.open(QIODevice::WriteOnly));
            file.write("previous file");
        }
        auto gate = std::make_shared<Gate>();
        auto calls = std::make_shared<std::atomic<int>>(0);
        auto options = testOptions();
        options.exportWriter = [gate, calls](QIODevice &file, const char *data, qint64 n) {
            gate->wait();
            return (*calls)++ == 0 ? file.write(data, std::min<qint64>(n, 16)) : qint64(-1);
        };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.show();
        std::vector<Packet> packets;
        packets.push_back(decodePacket(fixtures::icmp()));
        window.ingestBenchmark(std::move(packets));
        QSignalSpy done(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(path));
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 3000);
        QVERIFY(!window.close());
        gate->release();
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 5000);
        QVERIFY(!done.front()[0].toBool());
        QVERIFY(window.isVisible());
        QCOMPARE(window.packetModel()->rowCount(), 1);
        QFile file(path);
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), QByteArray("previous file"));
        QVERIFY(window.findChild<QLabel *>("captureStatus")->text().contains("失败"));
        QTest::qWait(120);
        QVERIFY(window.isVisible());
        QVERIFY(window.findChild<QPushButton *>("saveButton")->isEnabled());
        window.selectPacket(0);
        QVERIFY(waitForDetails(window));
        QVERIFY(window.findChild<QTreeWidget *>("fieldTree")->topLevelItemCount() > 0);
    }
    void stopDuringStartupAndPendingAction() {
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.capture = fakeCapture(gate);
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.show();
        QTest::mouseClick(window.findChild<QPushButton *>("startButton"), Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 3000);
        QCOMPARE(window.captureState(), MainWindow::CaptureState::Starting);
        auto *engine = window.findChild<CaptureEngine *>();
        QSignalSpy ended(engine, &CaptureEngine::finished);
        QElapsedTimer stop;
        stop.start();
        window.stopCapture();
        window.stopCapture();
        QVERIFY(stop.elapsed() < 100);
        QCOMPARE(window.captureState(), MainWindow::CaptureState::Stopping);
        QVERIFY(!window.findChild<QTabBar *>("sessionTabs")->isEnabled());
        int beats = 0;
        QTimer heartbeat;
        connect(&heartbeat, &QTimer::timeout, &window, [&] { ++beats; });
        heartbeat.setTimerType(Qt::PreciseTimer);
        heartbeat.start(20);
        QTRY_VERIFY_WITH_TIMEOUT(beats >= 3, 250);
        QCOMPARE(ended.count(), 0);
        gate->release();
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 3000);
        QCOMPARE(ended.count(), 1);
        window.stopCapture();
        QCOMPARE(ended.count(), 1);
    }
    void pendingOpenAndStaleNotifications() {
        QTemporaryDir dir;
        const auto path = sampleFile(dir);
        auto fileGate = std::make_shared<Gate>();
        auto starts = std::make_shared<std::atomic<int>>(0);
        auto options = testOptions();
        options.capture = fakeCapture({}, fileGate, starts);
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{fileGate};
        window.show();
        QTest::mouseClick(window.findChild<QPushButton *>("startButton"), Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(window.packetModel()->rowCount() > 0, 3000);
        auto *engine = window.findChild<CaptureEngine *>();
        const auto old = engine->generation();
        QVERIFY(window.openFile(path));
        QVERIFY(!window.openFile(path));
        QTRY_VERIFY_WITH_TIMEOUT(fileGate->entered.load(), 3000);
        QVERIFY(engine->generation() > old);
        QCOMPARE(starts->load(), 2);
        emit engine->opened(old, "过期开启");
        emit engine->failed(old, "过期错误");
        emit engine->finished(old);
        QCOMPARE(window.captureState(), MainWindow::CaptureState::Starting);
        QVERIFY(!window.findChild<QLabel *>("captureStatus")->text().contains("过期"));
        fileGate->release();
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 3000);
        QCOMPARE(window.packetModel()->rowCount(), 12);
        QCOMPARE(starts->load(), 2);
        window.findChild<QTabBar *>("sessionTabs")->setCurrentIndex(0);
        QVERIFY(window.packetModel()->rowCount() > 0);
    }
    void startupFailureAlwaysFinishes() {
        auto hooks = fakeCapture();
        hooks.run = [](const QString &, bool, std::stop_token, const CaptureHooks::Sink &,
                       const CaptureHooks::Opened &,
                       const LiveCaptureOptions &) { throw std::runtime_error("测试开启失败"); };
        CaptureEngine engine(nullptr, hooks);
        QSignalSpy failed(&engine, &CaptureEngine::failed), done(&engine, &CaptureEngine::finished);
        engine.startLive("fake-a");
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 3000);
        QCOMPARE(failed.count(), 1);
        QVERIFY(!engine.running());
        engine.requestStop();
        engine.requestStop();
        QCOMPARE(done.count(), 1);
    }
    void followRespondsOnlyToUserInput() {
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.capture = fakeCapture(gate);
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.resize(1100, 800);
        window.show();
        QTest::mouseClick(window.findChild<QPushButton *>("startButton"), Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 3000);
        std::vector<Packet> packets;
        for (int i = 0; i < 400; ++i)
            packets.push_back(decodePacket(fixtures::icmp()));
        window.packetModel()->append(std::move(packets));
        auto *table = window.findChild<QTableView *>("packetTable");
        auto *follow = window.findChild<QCheckBox *>("followLatest");
        table->scrollToBottom();
        QTest::qWait(30);
        QVERIFY(follow->isChecked());
        table->verticalScrollBar()->triggerAction(QAbstractSlider::SliderPageStepSub);
        QVERIFY(!follow->isChecked());
        window.selectPacket(10);
        QVERIFY(waitForDetails(window));
        auto *tree = window.findChild<QTreeWidget *>("fieldTree");
        auto *item = tree->topLevelItem(1)->child(0);
        tree->setCurrentItem(item);
        follow->setChecked(true);
        QTest::qWait(30);
        QCOMPARE(table->verticalScrollBar()->value(), table->verticalScrollBar()->maximum());
        QCOMPARE(tree->currentItem(), item);
        std::vector<Packet> more;
        for (int i = 0; i < 10001; ++i)
            more.push_back(decodePacket(fixtures::icmp()));
        window.packetModel()->append(std::move(more));
        QTest::qWait(30);
        QVERIFY(follow->isChecked());
        const auto index = window.packetModel()->index(10, 0);
        table->scrollTo(index);
        QTest::qWait(20);
        QTest::mouseClick(table->viewport(), Qt::LeftButton, Qt::NoModifier,
                          table->visualRect(index).center());
        QVERIFY(!follow->isChecked());
        window.stopCapture();
        gate->release();
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 3000);
    }
    void settingsRestoreOnlyAppliedValues() {
        QTemporaryDir dir;
        const auto input = sampleFile(dir), output = dir.filePath("saved.pcap");
        auto options = testOptions();
        options.capture = fakeCapture();
        {
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            window.show();
            window.setDarkTheme(true);
            window.resize(1050, 750);
            window.findChild<QComboBox *>("deviceSelector")->setCurrentIndex(1);
            auto *table = window.findChild<QTableView *>("packetTable");
            table->setColumnWidth(2, 222);
            QVERIFY(window.openFile(input));
            QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 3000);
            QSignalSpy done(&window, &MainWindow::saveFinished);
            QVERIFY(window.saveFile(output));
            QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 3000);
            window.findChild<QLineEdit *>("ipInput")->setText("192.0.2.1");
            window.findChild<QComboBox *>("ipDirection")->setCurrentIndex(1);
            window.findChild<QPushButton *>("applyFilterButton")->click();
            window.findChild<QLineEdit *>("ipInput")->setText("invalid draft");
            window.findChild<QPushButton *>("applyFilterButton")->click();
            QVERIFY(window.close());
        }
        QSettings saved(options.settingsFile, QSettings::IniFormat);
        QCOMPARE(saved.value("filter/ip").toString(), QString("192.0.2.1"));
        QCOMPARE(saved.value("files/openDirectory").toString(), dir.path());
        QCOMPARE(saved.value("files/saveDirectory").toString(), dir.path());
        MainWindow restored(nullptr, options);
        QVERIFY(waitForInterfaces(restored));
        QCOMPARE(restored.findChild<QAction *>("darkThemeAction")->isChecked(), true);
        QCOMPARE(restored.findChild<QLineEdit *>("ipInput")->text(), QString("192.0.2.1"));
        QCOMPARE(restored.findChild<QComboBox *>("ipDirection")->currentIndex(), 1);
        QCOMPARE(restored.findChild<QComboBox *>("deviceSelector")->currentData().toString(),
                 QString("fake-b"));
        QCOMPARE(restored.findChild<QTableView *>("packetTable")->columnWidth(2), 222);
        QVERIFY(
            restored.findChild<QPushButton *>("ipCondition")->toolTip().contains("IPv4 192.0.2.1"));
        QVERIFY(!restored.busy());
    }
    void invalidSettingsFallBackSafely() {
        auto options = testOptions();
        options.capture = fakeCapture();
        {
            QSettings saved(options.settingsFile, QSettings::IniFormat);
            saved.setValue("filter/ip", "999.2.3.4");
            saved.setValue("capture/device", "missing-adapter");
            saved.setValue("files/openDirectory", "Z:/missing-folder-etherscope");
            saved.setValue("files/saveDirectory", "Z:/missing-folder-etherscope");
            QWidget farAway;
            farAway.resize(1100, 750);
            farAway.move(50000, 50000);
            saved.setValue("ui/geometry", farAway.saveGeometry());
            saved.sync();
        }
        {
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            window.show();
            QVERIFY(!window.packetModel()->filter().ip);
            QVERIFY(window.findChild<QLineEdit *>("ipInput")->text().isEmpty());
            QCOMPARE(window.findChild<QComboBox *>("deviceSelector")->currentIndex(), -1);
            QVERIFY(!window.findChild<QPushButton *>("startButton")->isEnabled());
            QVERIFY(QGuiApplication::primaryScreen()->availableGeometry().intersects(
                window.frameGeometry()));
            QVERIFY(window.close());
        }
        QSettings saved(options.settingsFile, QSettings::IniFormat);
        QVERIFY(QDir(saved.value("files/openDirectory").toString()).exists());
        QVERIFY(QDir(saved.value("files/saveDirectory").toString()).exists());
        auto corrupt = testOptions();
        {
            QFile file(corrupt.settingsFile);
            QVERIFY(file.open(QIODevice::WriteOnly));
            file.write("[broken\nui/dark=true\n");
        }
        MainWindow window(nullptr, corrupt);
        QVERIFY(waitForInterfaces(window));
        QVERIFY(!window.packetModel()->filter().ip);
        QVERIFY(!window.busy());
    }
    void adapterReselectionEnablesCapture() {
        auto options = testOptions();
        options.capture = fakeCapture();
        {
            QSettings settings(options.settingsFile, QSettings::IniFormat);
            settings.setValue("capture/device", "removed-adapter");
        }
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        window.show();
        auto *devices = window.findChild<QComboBox *>("deviceSelector");
        auto *start = window.findChild<QPushButton *>("startButton");
        QCOMPARE(devices->currentIndex(), -1);
        QVERIFY(!start->isEnabled());
        devices->setCurrentIndex(1);
        QVERIFY(start->isEnabled());
        QTest::mouseClick(start, Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(window.packetModel()->rowCount() > 0, 3000);
        window.stopCapture();
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 3000);
        window.findChild<QAction *>("refreshAction")->trigger();
        QVERIFY(waitForInterfaces(window));
        QCOMPARE(devices->currentData().toString(), QString("fake-b"));
        QVERIFY(start->isEnabled());
    }
    void saveCompletionPreservesNewerError() {
        QTemporaryDir directory;
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.exportWriter = gatedWriter(gate);
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.show();
        std::vector<Packet> packets;
        packets.push_back(decodePacket(fixtures::icmp()));
        window.ingestBenchmark(std::move(packets));
        QSignalSpy done(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(directory.filePath("saved.pcap")));
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 3000);
        QVERIFY(window.openFile(directory.filePath("missing.pcap")));
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 3000);
        auto *status = window.findChild<QLabel *>("captureStatus");
        const auto error = status->text();
        QVERIFY(error.contains("无法打开"));
        gate->release();
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 3000);
        QVERIFY(done.front()[0].toBool());
        QCOMPARE(status->text(), error);
        QTest::qWait(150);
        QCOMPARE(status->text(), error);
    }
    void filterPreservesMatchingInspection() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::samples())
            packets.push_back(decodePacket(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        window.selectPacket(2);
        QVERIFY(waitForDetails(window));
        auto *table = window.findChild<QTableView *>("packetTable");
        auto *tree = window.findChild<QTreeWidget *>("fieldTree");
        auto *hex = window.findChild<QPlainTextEdit *>("hexView");
        auto *field = tree->topLevelItem(1)->child(0);
        tree->setCurrentItem(field);
        tree->topLevelItem(0)->setExpanded(false);
        const auto bytes = hex->toPlainText();
        auto *apply = window.findChild<QPushButton *>("applyFilterButton");
        window.findChild<QComboBox *>("protocolFilter")->setCurrentText("ICMP");
        apply->click();
        QCOMPARE(window.packetModel()->packetAt(table->currentIndex().row())->id, std::uint64_t(3));
        QCOMPARE(tree->currentItem(), field);
        QVERIFY(!tree->topLevelItem(0)->isExpanded());
        QCOMPARE(hex->toPlainText(), bytes);
        window.findChild<QPushButton *>("clearFilterButton")->click();
        QCOMPARE(window.packetModel()->packetAt(table->currentIndex().row())->id, std::uint64_t(3));
        QCOMPARE(tree->currentItem(), field);
        window.findChild<QComboBox *>("protocolFilter")->setCurrentText("UDP");
        apply->click();
        QCOMPARE(window.packetModel()->packetAt(table->currentIndex().row())->protocol,
                 std::string("UDP"));
        window.findChild<QLineEdit *>("ipInput")->setText("192.0.2.200");
        apply->click();
        QCOMPARE(window.packetModel()->rowCount(), 0);
        QCOMPARE(tree->topLevelItemCount(), 0);
        QVERIFY(hex->toPlainText().isEmpty());
    }
    void fileBackpressureAndGeneration() {
        QTemporaryDir dir;
        auto path = dir.filePath("large.pcap");
        auto sample = decodePacket(fixtures::icmp());
        std::vector<const Packet *> refs(15000, &sample);
        {
            std::ofstream out(std::filesystem::path(path.toStdWString()), std::ios::binary);
            writePcap(out, refs);
        }
        CaptureEngine engine;
        QSignalSpy errors(&engine, &CaptureEngine::failed);
        engine.startFile(path);
        auto firstGeneration = engine.generation();
        QTest::qWait(50);
        // Producer must wait for a drain instead of silently dropping file records.
        auto first = engine.takeBatch();
        QVERIFY(first.size() <= 2048);
        std::size_t received = first.size();
        QElapsedTimer deadline;
        deadline.start();
        while (engine.running() && deadline.elapsed() < 10000) {
            QTest::qWait(5);
            received += engine.takeBatch().size();
        }
        engine.stop();
        received += engine.takeBatch().size();
        QCOMPARE(received, std::size_t(15000));
        QCOMPARE(engine.counters().queueDropped, std::uint64_t(0));
        QCOMPARE(errors.count(), 0);
        engine.startFile(path);
        QVERIFY(engine.generation() > firstGeneration);
        engine.stop();
        QElapsedTimer stop;
        stop.start();
        engine.stop();
        QVERIFY(stop.elapsed() < 1000);
        engine.startFile(path);
        QTRY_COMPARE_WITH_TIMEOUT(engine.counters().received, std::uint64_t(2048), 5000);
        stop.restart();
        engine.stop();
        QVERIFY(stop.elapsed() < 1000);
        QCOMPARE(engine.counters().queueDropped, std::uint64_t(0));
    }
    void boundedDrainAndFullQueueStop() {
        auto hooks = fakeCapture();
        hooks.run = [](const QString &, bool, std::stop_token stop, const CaptureHooks::Sink &sink,
                       const CaptureHooks::Opened &opened, const LiveCaptureOptions &) {
            opened("捕获中");
            for (int i = 0; i < 10000; ++i)
                sink(fixtures::icmp());
            while (!stop.stop_requested())
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        };
        CaptureEngine engine(nullptr, hooks);
        QSignalSpy done(&engine, &CaptureEngine::finished);
        engine.startLive("fake-a");
        QTRY_COMPARE_WITH_TIMEOUT(engine.counters().received, std::uint64_t(10000), 5000);
        const auto retained = engine.counters().queuedPackets;
        QVERIFY(retained > 0 && retained <= 8192);
        QCOMPARE(engine.counters().queueDropped, std::uint64_t(10000) - retained);
        QVERIFY(engine.counters().peakQueuedEstimatedBytes <= 32 * 1024 * 1024);
        QElapsedTimer timer;
        timer.start();
        engine.requestStop();
        engine.requestStop();
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 1000);
        QVERIFY(timer.elapsed() < 1000);
        std::size_t drained = 0;
        while (engine.counters().queuedPackets) {
            auto batch = engine.takeBatch(37);
            QVERIFY(batch.size() <= 37);
            drained += batch.size();
        }
        QCOMPARE(drained, static_cast<std::size_t>(retained));
        QCOMPARE(engine.counters().queuedBytes, std::uint64_t(0));
        QCOMPARE(engine.counters().enqueued + engine.counters().queueDropped,
                 engine.counters().received);
    }
    void queuedSnapshotBoundaryAndFinalDrain() {
        QTemporaryDir directory;
        auto source = std::make_shared<Gate>();
        auto writer = std::make_shared<Gate>();
        auto options = testOptions();
        options.capture = fakeCapture();
        options.exportWriter = gatedWriter(writer);
        options.capture.run =
            [source](const QString &, bool, std::stop_token stop, const CaptureHooks::Sink &sink,
                     const CaptureHooks::Opened &opened, const LiveCaptureOptions &) {
                opened("捕获中");
                for (int i = 0; i < 5000; ++i) {
                    if (i == 3000)
                        source->wait();
                    auto raw = fixtures::icmp();
                    raw.timestampNs += std::int64_t(i) * 1000000;
                    sink(std::move(raw));
                }
                while (!stop.stop_requested())
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate releaseSource{source}, releaseWriter{writer};
        window.show();
        window.findChild<QPushButton *>("startButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(source->entered.load(), 5000);
        QCOMPARE(window.captureCounters().enqueued, std::uint64_t(3000));
        QTRY_COMPARE(window.captureState(), MainWindow::CaptureState::Running);
        window.findChild<QComboBox *>("protocolFilter")->setCurrentText("UDP");
        window.findChild<QPushButton *>("applyFilterButton")->click();
        const auto path = directory.filePath("snapshot.pcap");
        QSignalSpy saved(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(path));
        QVERIFY(!window.saveFile(path));
        source->release();
        QTRY_VERIFY_WITH_TIMEOUT(writer->entered.load(), 5000);
        QTRY_COMPARE_WITH_TIMEOUT(window.sessionStats().received, std::uint64_t(5000), 5000);
        QCOMPARE(window.packetModel()->rowCount(), 0);
        window.stopCapture();
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 1000);
        QCOMPARE(window.captureCounters().queuedPackets, std::uint64_t(0));
        writer->release();
        QTRY_COMPARE_WITH_TIMEOUT(saved.count(), 1, 5000);
        QVERIFY(saved.front()[0].toBool());
        QCOMPARE(saved.front()[2].toULongLong(), qulonglong(3000));
        PcapReader reader(std::filesystem::path(path.toStdWString()));
        for (int i = 0; i < 3000; ++i) {
            auto raw = reader.next();
            QVERIFY(raw);
            QCOMPARE(raw->bytes, fixtures::icmp().bytes);
            QCOMPARE(raw->timestampNs, fixtures::icmp().timestampNs + std::int64_t(i) * 1000000);
        }
        QVERIFY(!reader.next());
    }
    void responsiveLayoutAndStatisticsRestore() {
        auto options = testOptions();
        {
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            window.show();
            window.resize(1000, 700);
            QTest::qWait(30);
            window.findChild<QPushButton *>("addressFilterToggle")->setChecked(true);
            auto *mac = window.findChild<QLineEdit *>("macInput");
            auto *ip = window.findChild<QLineEdit *>("ipInput");
            QVERIFY(ip->mapTo(&window, QPoint()).y() > mac->mapTo(&window, QPoint()).y());
            auto *statistics = window.findChild<QCheckBox *>("statisticsToggle");
            statistics->setChecked(false);
            QVERIFY(!window.findChild<QWidget *>("trafficChart")->isVisible());
            window.resize(1360, 860);
            QTest::qWait(30);
            QCOMPARE(ip->mapTo(&window, QPoint()).y(), mac->mapTo(&window, QPoint()).y());
            std::vector<Packet> packets;
            for (int i = 0; i < 2; ++i)
                packets.push_back(decodePacket(fixtures::icmp()));
            window.ingestBenchmark(std::move(packets));
            window.selectPacket(0);
            QVERIFY(waitForDetails(window));
            auto *fields = window.findChild<QTreeWidget *>("fieldTree");
            QVERIFY(fields->topLevelItemCount() > 0);
            fields->topLevelItem(0)->setExpanded(false);
            window.selectPacket(1);
            QVERIFY(waitForDetails(window));
            QVERIFY(!fields->topLevelItem(0)->isExpanded());
            QVERIFY(window.close());
        }
        MainWindow restored(nullptr, options);
        QVERIFY(waitForInterfaces(restored));
        restored.show();
        QVERIFY(!restored.findChild<QCheckBox *>("statisticsToggle")->isChecked());
    }
    void addressDraftAndImmediateProtocol() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::samples())
            packets.push_back(decodePacket(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        auto *toggle = window.findChild<QPushButton *>("addressFilterToggle");
        auto *panel = window.findChild<QWidget *>("addressFilterPanel");
        QVERIFY(!panel->isVisible());
        QTest::mouseClick(toggle, Qt::LeftButton);
        QVERIFY(panel->isVisible());
        auto *ip = window.findChild<QLineEdit *>("ipInput");
        auto *mac = window.findChild<QLineEdit *>("macInput");
        mac->setText("02:00:00:00:00:01");
        ip->setText("192.0.2.1");
        window.findChild<QComboBox *>("ipDirection")->setCurrentIndex(1);
        QTest::keyClick(ip, Qt::Key_Return);
        QVERIFY(window.packetModel()->filter().ip);
        QVERIFY(window.packetModel()->filter().mac);
        auto *ipChip = window.findChild<QPushButton *>("ipCondition");
        QCOMPARE(ipChip->toolTip(), QString("源 IPv4 192.0.2.1"));
        ip->setText("invalid draft");
        QTest::keyClick(ip, Qt::Key_Return);
        QVERIFY(window.findChild<QLabel *>("ipError")->isVisible());
        const auto previous = window.packetModel()->filter();
        QTest::keyClick(ip, Qt::Key_Escape);
        QVERIFY(!panel->isVisible());
        QCOMPARE(window.packetModel()->filter(), previous);
        window.findChild<QComboBox *>("protocolFilter")->setCurrentText("UDP");
        QCOMPARE(window.packetModel()->rowCount(), 1);
        QCOMPARE(ip->text(), QString("invalid draft"));
        QVERIFY(window.packetModel()->filter().ip);
        QCOMPARE(ipChip->toolTip(), QString("源 IPv4 192.0.2.1"));
        QTest::mouseClick(ipChip, Qt::LeftButton);
        QVERIFY(!window.packetModel()->filter().ip);
        QVERIFY(window.packetModel()->filter().mac);
        QVERIFY(ip->text().isEmpty());
        QTest::mouseClick(window.findChild<QPushButton *>("macCondition"), Qt::LeftButton);
        QVERIFY(!window.packetModel()->filter().mac);
        QTest::mouseClick(window.findChild<QPushButton *>("protocolCondition"), Qt::LeftButton);
        QCOMPARE(window.packetModel()->rowCount(), 12);
        QTest::mouseClick(toggle, Qt::LeftButton);
        mac->setText("bad");
        ip->setText("bad");
        QTest::keyClick(ip, Qt::Key_Return);
        QVERIFY(window.findChild<QLabel *>("macError")->isVisible());
        QVERIFY(window.findChild<QLabel *>("ipError")->isVisible());
        QCOMPARE(window.packetModel()->rowCount(), 12);
    }
    void presentationSettingsAndLongConditions() {
        auto options = testOptions();
        {
            QSettings settings(options.settingsFile, QSettings::IniFormat);
            settings.setValue("ui/statistics", true);
            settings.setValue("ui/columns", "obsolete");
        }
        {
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            window.show();
            window.resize(1024, 768);
            auto *table = window.findChild<QTableView *>("packetTable");
            QVERIFY(table->isColumnHidden(6));
            table->setColumnHidden(6, false);
            table->setColumnWidth(2, 220);
            QVERIFY(window.findChild<QCheckBox *>("statisticsToggle")->isChecked());
            window.findChild<QPushButton *>("addressFilterToggle")->setChecked(true);
            window.findChild<QLineEdit *>("macInput")->setText("02:00:00:00:00:01");
            window.findChild<QLineEdit *>("ipInput")->setText(
                "1234:5678:9abc:def0:1234:5678:9abc:def0");
            window.findChild<QComboBox *>("ipDirection")->setCurrentIndex(2);
            window.findChild<QPushButton *>("applyFilterButton")->click();
            window.findChild<QComboBox *>("protocolFilter")->setCurrentText("IPv6");
            QTest::qWait(40);
            auto *chip = window.findChild<QPushButton *>("ipCondition");
            QVERIFY(chip->isVisible());
            QCOMPARE(chip->toolTip(), QString("目的 IPv6 1234:5678:9abc:def0:1234:5678:9abc:def0"));
            QVERIFY(chip->text().contains(QChar(0x2026)));
            QVERIFY(chip->accessibleName().contains(chip->toolTip()));
            for (const auto *name : {"addressFilterToggle", "ipCondition", "macCondition",
                                     "protocolCondition", "followLatest", "statisticsToggle"}) {
                auto *widget = window.findChild<QWidget *>(name);
                const QRect rectangle(widget->mapTo(&window, QPoint()), widget->size());
                QVERIFY(window.rect().contains(rectangle));
            }
            window.findChild<QPushButton *>("diagnosticsToggle")->click();
            QVERIFY(window.findChild<QWidget *>("diagnosticPanel")->isVisible());
            QVERIFY(window.close());
        }
        MainWindow restored(nullptr, options);
        QVERIFY(waitForInterfaces(restored));
        restored.show();
        QVERIFY(restored.findChild<QPushButton *>("addressFilterToggle")->isChecked());
        QVERIFY(!restored.findChild<QWidget *>("diagnosticPanel")->isVisible());
        auto *table = restored.findChild<QTableView *>("packetTable");
        QVERIFY(!table->isColumnHidden(6));
        QCOMPARE(table->columnWidth(2), 220);
        QVERIFY(
            restored.findChild<QPushButton *>("ipCondition")->toolTip().startsWith("目的 IPv6"));
    }
    void icmpSubtypeFilteringAndHiddenExport() {
        auto options = testOptions();
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::samples())
            packets.push_back(decodePacket(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        auto *protocol = window.findChild<QComboBox *>("protocolFilter");
        auto *type = window.findChild<QComboBox *>("icmpTypeFilter");
        auto *group = window.findChild<QWidget *>("icmpTypeGroup");
        QVERIFY(!group->isVisible());
        protocol->setCurrentText("ICMP");
        QVERIFY(group->isVisible());
        QVERIFY(!window.packetModel()->filter().icmpType);
        for (int value : {8, 0, 11, 3}) {
            type->setCurrentIndex(type->findData(value));
            QVERIFY(window.packetModel()->rowCount() > 0);
            for (int row = 0; row < window.packetModel()->rowCount(); ++row)
                QCOMPARE(int(*window.packetModel()->packetAt(row)->icmpType), value);
        }
        auto *ip = window.findChild<QLineEdit *>("ipInput");
        ip->setText("192.0.2.1");
        window.findChild<QPushButton *>("applyFilterButton")->click();
        QCOMPARE(int(*window.packetModel()->filter().icmpType), 3);
        ip->setText("invalid draft");
        type->setCurrentIndex(type->findData(11));
        QCOMPARE(ip->text(), QString("invalid draft"));
        QVERIFY(window.packetModel()->filter().ip);
        QCOMPARE(window.packetModel()->rowCount(), 1);
        QTemporaryDir directory;
        QSignalSpy saved(&window, &MainWindow::saveFinished);
        const auto path = directory.filePath("all.pcap");
        QVERIFY(window.saveFile(path));
        QTRY_COMPARE_WITH_TIMEOUT(saved.count(), 1, 3000);
        QVERIFY(saved.front()[0].toBool());
        QCOMPARE(saved.front()[2].toULongLong(), qulonglong(12));
        PcapReader reader(std::filesystem::path(path.toStdWString()));
        const auto expected = fixtures::samples();
        std::size_t count = 0;
        while (auto raw = reader.next()) {
            QVERIFY(count < expected.size());
            QVERIFY(raw->bytes == expected[count++].bytes);
        }
        QCOMPARE(count, expected.size());
        window.findChild<QPushButton *>("icmpCondition")->click();
        QVERIFY(!window.packetModel()->filter().icmpType);
        QCOMPARE(window.packetModel()->filter().protocol, std::string("ICMP"));
        QVERIFY(window.packetModel()->rowCount() > 1);
        type->setCurrentIndex(type->findData(0));
        protocol->setCurrentText("UDP");
        QVERIFY(!group->isVisible());
        QVERIFY(!window.packetModel()->filter().icmpType);
        protocol->setCurrentText("ICMP");
        QCOMPARE(type->currentIndex(), 0);
        type->setCurrentIndex(type->findData(3));
        window.findChild<QPushButton *>("protocolCondition")->click();
        QVERIFY(!window.packetModel()->filter().icmpType);
        QVERIFY(window.packetModel()->filter().protocol.empty());
        QVERIFY(!group->isVisible());
    }
    void icmpSubtypeSettingsCompatibility() {
        for (int value : {8, 0, 11, 3}) {
            auto options = testOptions();
            {
                MainWindow window(nullptr, options);
                QVERIFY(waitForInterfaces(window));
                window.findChild<QComboBox *>("protocolFilter")->setCurrentText("ICMP");
                auto *type = window.findChild<QComboBox *>("icmpTypeFilter");
                type->setCurrentIndex(type->findData(value));
                QVERIFY(window.close());
            }
            {
                MainWindow restored(nullptr, options);
                QVERIFY(waitForInterfaces(restored));
                QCOMPARE(int(*restored.packetModel()->filter().icmpType), value);
                QCOMPARE(restored.findChild<QComboBox *>("icmpTypeFilter")->currentData().toInt(),
                         value);
            }
        }
        for (const auto &value :
             QList<QVariant>{QVariant(), QVariant("bad"), QVariant(13), QVariant(256)}) {
            auto options = testOptions();
            {
                QSettings settings(options.settingsFile, QSettings::IniFormat);
                settings.setValue("filter/protocol", "ICMP");
                settings.setValue("filter/ip", "192.0.2.1");
                if (value.isValid())
                    settings.setValue("filter/icmpType", value);
            }
            MainWindow restored(nullptr, options);
            QVERIFY(waitForInterfaces(restored));
            QVERIFY(!restored.packetModel()->filter().icmpType);
            QVERIFY(restored.packetModel()->filter().ip);
            QCOMPARE(restored.packetModel()->filter().protocol, std::string("ICMP"));
            restored.findChild<QComboBox *>("protocolFilter")->setCurrentText("UDP");
            QVERIFY(restored.close());
            QSettings saved(options.settingsFile, QSettings::IniFormat);
            QVERIFY(!saved.contains("filter/icmpType"));
        }
    }
    void checksumDetailsAndIcmpLayout() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::analysisSamples())
            packets.push_back(decodePacket(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        window.selectPacket(0);
        QVERIFY(waitForDetails(window));
        auto *tree = window.findChild<QTreeWidget *>("fieldTree");
        const auto matches = tree->findItems("校验状态", Qt::MatchExactly | Qt::MatchRecursive, 0);
        QCOMPARE(matches.size(), 2);
        for (auto *item : matches) {
            QCOMPARE(item->text(1), QString("一致"));
            tree->setCurrentItem(item);
            QVERIFY(!window.findChild<QPlainTextEdit *>("hexView")->extraSelections().empty());
        }
        auto *protocol = window.findChild<QComboBox *>("protocolFilter");
        protocol->setCurrentText("ICMP");
        auto *type = window.findChild<QComboBox *>("icmpTypeFilter");
        type->setCurrentIndex(type->findData(8));
        window.findChild<QLineEdit *>("macInput")->setText("02:00:00:00:00:01");
        window.findChild<QLineEdit *>("ipInput")->setText("2001:db8:1234:5678:abcd:1234:5678:9abc");
        window.findChild<QPushButton *>("applyFilterButton")->click();
        for (bool dark : {true, false})
            for (const QSize size : {QSize(1024, 768), QSize(1440, 900)}) {
                window.setDarkTheme(dark);
                window.resize(size);
                QTest::qWait(30);
                QCOMPARE(window.size(), size);
                for (const auto *name :
                     {"sessionTabs", "protocolFilter", "icmpTypeGroup", "icmpTypeFilter",
                      "addressFilterToggle", "protocolCondition", "icmpCondition", "macCondition",
                      "ipCondition", "followLatest", "statisticsToggle"}) {
                    auto *widget = window.findChild<QWidget *>(name);
                    QVERIFY(widget && widget->isVisible());
                    QVERIFY2(window.rect().contains(
                                 QRect(widget->mapTo(&window, QPoint()), widget->size())),
                             name);
                }
                if (size.width() == 1440)
                    QVERIFY(
                        double(window.findChild<QSplitter *>("packetDetailSplitter")->height()) /
                            window.centralWidget()->height() >=
                        0.75);
                const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
                if (!screenshots.isEmpty()) {
                    QDir().mkpath(screenshots);
                    QVERIFY(window.grab().save(
                        screenshots +
                        QString("/icmp-%1-%2.png").arg(dark ? "dark" : "light").arg(size.width())));
                }
            }
    }
    void packetMarkersAndColumnMenu() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        std::vector<Packet> packets;
        for (auto raw : fixtures::samples())
            packets.push_back(decodePacket(std::move(raw)));
        window.ingestBenchmark(std::move(packets));
        auto *model = window.packetModel();
        QVERIFY(!model->data(model->index(0, 0), Qt::DecorationRole).isValid());
        QVERIFY(model->data(model->index(0, 6), Qt::DisplayRole).toString().isEmpty());
        QVERIFY(
            !qvariant_cast<QIcon>(model->data(model->index(9, 0), Qt::DecorationRole)).isNull());
        QVERIFY(
            !qvariant_cast<QIcon>(model->data(model->index(11, 0), Qt::DecorationRole)).isNull());
        QVERIFY(!model->data(model->index(11, 2), Qt::ForegroundRole).isValid());
        QVERIFY(
            model->data(model->index(11, 0), Qt::AccessibleTextRole).toString().contains("异常"));
        QVERIFY(model->data(model->index(9, 0), Qt::ToolTipRole).toString().contains("分片"));
        auto *table = window.findChild<QTableView *>("packetTable");
        QVERIFY(table->isColumnHidden(6));
        bool found = false;
        QTimer::singleShot(0, &window, [&] {
            if (auto *menu = qobject_cast<QMenu *>(QApplication::activePopupWidget())) {
                for (auto *action : menu->actions())
                    if (action->text() == "状态") {
                        action->trigger();
                        found = true;
                    }
                menu->close();
            }
        });
        table->horizontalHeader()->customContextMenuRequested(QPoint(10, 10));
        QVERIFY(found);
        QVERIFY(!table->isColumnHidden(6));
        window.findChild<QAction *>("darkThemeAction")->trigger();
        QVERIFY(!window.findChild<QAction *>("darkThemeAction")->isChecked());
        window.findChild<QAction *>("refreshAction")->trigger();
        QVERIFY(waitForInterfaces(window));
        QCOMPARE(window.findChild<QComboBox *>("deviceSelector")->count(), 1);
    }
    void workspaceRatioAndCollapsedDefaults() {
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        window.resize(1440, 900);
        QTest::qWait(40);
        QVERIFY(!window.findChild<QWidget *>("addressFilterPanel")->isVisible());
        QVERIFY(!window.findChild<QCheckBox *>("statisticsToggle")->isChecked());
        QVERIFY(!window.findChild<QWidget *>("diagnosticPanel")->isVisible());
        auto *workspace = window.centralWidget();
        auto *content = window.findChild<QSplitter *>("packetDetailSplitter");
        QVERIFY(double(content->height()) / workspace->height() >= 0.75);
        auto *strip = window.findChild<QWidget *>("sessionStrip");
        const auto top = strip->mapTo(&window, QPoint()).y();
        for (const auto *name : {"sessionTabs", "protocolFilter", "addressFilterToggle",
                                 "followLatest", "statisticsToggle"}) {
            auto *widget = window.findChild<QWidget *>(name);
            const auto position = widget->mapTo(&window, QPoint());
            QVERIFY(position.y() >= top);
            QVERIFY(position.y() + widget->height() <= top + strip->height());
        }
        window.resize(1024, 768);
        window.findChild<QPushButton *>("addressFilterToggle")->click();
        QTest::qWait(30);
        for (const auto *name : {"macInput", "ipInput", "applyFilterButton", "clearFilterButton"}) {
            auto *widget = window.findChild<QWidget *>(name);
            QVERIFY(
                window.rect().contains(QRect(widget->mapTo(&window, QPoint()), widget->size())));
        }
    }
    void diagnosticDropCounts() {
        auto filled = std::make_shared<std::atomic<bool>>(false);
        auto options = testOptions();
        options.capture.run =
            [filled](const QString &, bool, std::stop_token stop, const CaptureHooks::Sink &sink,
                     const CaptureHooks::Opened &opened, const LiveCaptureOptions &) {
                opened("捕获中");
                for (int i = 0; i < 10000; ++i)
                    sink(fixtures::icmp());
                *filled = true;
                while (!stop.stop_requested())
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        window.show();
        window.findChild<QPushButton *>("startButton")->click();
        QTRY_COMPARE_WITH_TIMEOUT(window.captureState(), MainWindow::CaptureState::Running, 1000);
        QElapsedTimer deadline;
        deadline.start();
        while (!filled->load() && deadline.elapsed() < 3000)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        QVERIFY(filled->load());
        const auto dropped = window.captureCounters().queueDropped;
        QVERIFY(dropped > 0);
        window.stopCapture();
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 1000);
        auto *diagnostics = window.findChild<QPushButton *>("diagnosticsToggle");
        QVERIFY(diagnostics->property("warning").toBool());
        QCOMPARE(window.findChild<QLabel *>("droppedCount")->text(), QString::number(dropped));
        QTest::mouseClick(diagnostics, Qt::LeftButton);
        QVERIFY(window.findChild<QLabel *>("diagnosticReceived")->isVisible());
        QCOMPARE(window.findChild<QLabel *>("diagnosticReceived")->text(), QString("10000"));
        QCOMPARE(window.findChild<QLabel *>("diagnosticParsed")->text(),
                 QString::number(10000 - dropped));
        QCOMPARE(window.findChild<QLabel *>("diagnosticQueueDropped")->text(),
                 QString::number(dropped));
        QCOMPARE(window.findChild<QLabel *>("diagnosticDriverDropped")->text(), QString("未知"));
        QCOMPARE(window.findChild<QLabel *>("capturedCount")->text(), QString("10000"));
    }
    void keyboardActions() {
        auto refreshes = std::make_shared<int>(0);
        auto options = testOptions();
        options.capture.interfaces = [refreshes](QString &error) {
            ++*refreshes;
            error.clear();
            return std::vector<CaptureInterface>{{"keyboard", "测试网卡", "192.0.2.1"}};
        };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        window.show();
        window.activateWindow();
        QTest::qWait(30);
        QCOMPARE(*refreshes, 1);
        QTest::keyClick(&window, Qt::Key_F5);
        QVERIFY(waitForInterfaces(window));
        QCOMPARE(*refreshes, 2);
        std::vector<Packet> packets;
        packets.push_back(decodePacket(fixtures::icmp()));
        window.ingestBenchmark(std::move(packets));
        window.findChild<QLineEdit *>("ipInput")->setText("192.0.2.1");
        QTest::keyClick(&window, Qt::Key_Return, Qt::ControlModifier);
        QVERIFY(window.packetModel()->filter().ip);
        QVERIFY(window.findChild<QWidget *>("addressFilterPanel")->isVisible());
        const bool nativeDialogs = QCoreApplication::testAttribute(Qt::AA_DontUseNativeDialogs);
        QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, true);
        for (const auto &action :
             {std::pair{"openButton", Qt::Key_O}, std::pair{"saveButton", Qt::Key_S}}) {
            window.activateWindow();
            QTest::qWait(30);
            QSignalSpy clicks(window.findChild<QPushButton *>(action.first), &QPushButton::clicked);
            bool dialogShown = false;
            QTimer::singleShot(0, &window, [&] {
                if (auto *dialog = qobject_cast<QFileDialog *>(QApplication::activeModalWidget())) {
                    dialogShown = true;
                    dialog->reject();
                }
            });
            QTest::keyClick(&window, action.second, Qt::ControlModifier);
            QCOMPARE(clicks.count(), 1);
            QVERIFY(dialogShown);
        }
        QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, nativeDialogs);
    }
    void slowDiscoveryAndStaleReply() {
        auto gate = std::make_shared<Gate>();
        auto calls = std::make_shared<std::atomic<int>>(0);
        auto options = testOptions();
        options.capture.interfaces = [gate, calls](QString &error) {
            ++*calls;
            gate->wait();
            error.clear();
            return CaptureInterfaces{{"slow", "慢查询", "192.0.2.1"}};
        };
        MainWindow window(nullptr, options);
        ReleaseGate release{gate};
        window.show();
        QVERIFY(window.discovering());
        QVERIFY(!window.findChild<QPushButton *>("startButton")->isEnabled());
        QVERIFY(window.findChild<QPushButton *>("openButton")->isEnabled());
        int beats = 0;
        QTimer heartbeat;
        connect(&heartbeat, &QTimer::timeout, this, [&] { ++beats; });
        heartbeat.setTimerType(Qt::PreciseTimer);
        heartbeat.start(5);
        QTRY_VERIFY_WITH_TIMEOUT(beats >= 5, 250);
        QVERIFY(gate->entered);
        auto *preparation = window.findChild<PreparationService *>();
        QVERIFY(!preparation->requestInterfaces());
        QCOMPARE(calls->load(), 1);
        gate->release();
        QVERIFY(waitForInterfaces(window));
        auto *selector = window.findChild<QComboBox *>("deviceSelector");
        QCOMPARE(selector->currentData().toString(), QString("slow"));
        emit preparation->interfacesReady(preparation->interfaceGeneration() - 1,
                                          {{"old", "过期网卡", ""}}, "过期错误", false);
        QTest::qWait(10);
        QCOMPARE(selector->currentData().toString(), QString("slow"));
    }
    void closeWaitsForDiscovery() {
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.capture.interfaces = [gate](QString &error) {
            gate->wait();
            error.clear();
            return CaptureInterfaces{};
        };
        MainWindow window(nullptr, options);
        ReleaseGate release{gate};
        window.show();
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 1000);
        QVERIFY(!window.close());
        QVERIFY(window.isVisible());
        QTest::qWait(40);
        QVERIFY(window.isVisible());
        gate->release();
        QTRY_VERIFY_WITH_TIMEOUT(!window.isVisible(), 3000);
    }
    void preparedFileOpensOnceAndReportsResult() {
        QTemporaryDir dir;
        const auto path = sampleFile(dir);
        auto options = testOptions();
        auto opens = std::make_shared<std::atomic<int>>(0);
        options.prepareFile = [opens](const QString &path, std::stop_token) {
            ++*opens;
            auto reader = std::make_shared<PcapReader>(std::filesystem::path(path.toStdWString()));
            QFile changed(path);
            if (!changed.open(QIODevice::ReadWrite) || changed.write("BAD!") != 4 ||
                !changed.flush())
                throw std::runtime_error("测试文件修改失败");
            return reader;
        };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        window.show();
        QSignalSpy done(&window, &MainWindow::fileOpenFinished);
        QVERIFY(window.openFile(path));
        QVERIFY(!window.openFile(path));
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 3000);
        QCOMPARE(done.front()[1].value<MainWindow::FileOpenResult>(),
                 MainWindow::FileOpenResult::Success);
        QCOMPARE(opens->load(), 1);
        QCOMPARE(window.packetModel()->rowCount(), 12);
        QVERIFY(!window.busy());
    }
    void preparationFailureKeepsLiveCapture() {
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.capture = fakeCapture();
        options.prepareFile = [gate](const QString &, std::stop_token) -> PreparedFile {
            gate->wait();
            throw std::runtime_error("测试文件失败");
        };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.show();
        window.findChild<QPushButton *>("startButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(window.sessionStats().received >= 20, 3000);
        const auto before = window.sessionStats().received;
        QSignalSpy done(&window, &MainWindow::fileOpenFinished);
        QVERIFY(window.openFile("slow.pcap"));
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 1000);
        QVERIFY(!window.findChild<QTabBar *>("sessionTabs")->isEnabled());
        QTest::qWait(80);
        QVERIFY(window.captureCounters().received > before);
        QVERIFY(window.findChild<QPushButton *>("saveButton")->isEnabled());
        int beats = 0;
        QTimer timer;
        connect(&timer, &QTimer::timeout, this, [&] { ++beats; });
        timer.setTimerType(Qt::PreciseTimer);
        timer.start(5);
        QTRY_VERIFY_WITH_TIMEOUT(beats >= 4, 250);
        gate->release();
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 3000);
        QCOMPARE(done.front()[1].value<MainWindow::FileOpenResult>(),
                 MainWindow::FileOpenResult::Failure);
        QCOMPARE(window.findChild<QTabBar *>("sessionTabs")->currentIndex(), 0);
        QVERIFY(window.sessionStats().received >= before);
        QCOMPARE(window.captureState(), MainWindow::CaptureState::Running);
        window.stopCapture();
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 1000);
    }
    void cancelAndCloseDuringFilePreparation() {
        for (bool closeWindow : {false, true}) {
            QTemporaryDir dir;
            const auto path = sampleFile(dir);
            auto gate = std::make_shared<Gate>();
            auto options = testOptions();
            options.prepareFile = [gate](const QString &path,
                                         std::stop_token stop) -> PreparedFile {
                gate->wait();
                if (stop.stop_requested())
                    return {};
                return std::make_shared<PcapReader>(std::filesystem::path(path.toStdWString()));
            };
            MainWindow window(nullptr, options);
            QVERIFY(waitForInterfaces(window));
            ReleaseGate release{gate};
            window.show();
            std::vector<Packet> packets;
            packets.push_back(decodePacket(fixtures::icmp()));
            window.ingestBenchmark(std::move(packets));
            QSignalSpy done(&window, &MainWindow::fileOpenFinished);
            QVERIFY(window.openFile(path));
            QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 1000);
            if (closeWindow) {
                QVERIFY(!window.close());
                QVERIFY(window.isVisible());
            } else {
                window.stopCapture();
                window.stopCapture();
            }
            gate->release();
            QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 3000);
            QCOMPARE(done.front()[1].value<MainWindow::FileOpenResult>(),
                     MainWindow::FileOpenResult::Cancelled);
            if (closeWindow)
                QTRY_VERIFY_WITH_TIMEOUT(!window.isVisible(), 3000);
            else {
                QVERIFY(!window.busy());
                QVERIFY(window.isVisible());
                QCOMPARE(window.packetModel()->rowCount(), 1);
            }
        }
    }
    void denseFieldsSnapshotAndSeparateCells() {
        QTemporaryDir dir;
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.exportWriter = gatedWriter(gate);
        options.capture.interfaces = [](QString &error) {
            error.clear();
            return CaptureInterfaces{{"device", "设备·原名", "2001:db8::1"}};
        };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.show();
        auto *selector = window.findChild<QComboBox *>("deviceSelector");
        QCOMPARE(selector->currentText(), QString("设备·原名"));
        QCOMPARE(selector->model()->index(0, 1).data().toString(), QString("2001:db8::1"));
        std::vector<std::uint8_t> payload(24, 0);
        payload[0] = 135;
        for (int i = 0; i < 8000; ++i)
            payload.insert(payload.end(), {99, 1, 0, 0, 0, 0, 0, 0});
        const auto raw = fixtures::ipv6(58, payload, 255);
        std::vector<Packet> packets;
        for (int i = 0; i < 180; ++i)
            packets.push_back(decodePacket(raw));
        window.ingestBenchmark(std::move(packets));
        const auto retained = window.packetModel()->rowCount();
        QVERIFY(retained > 0 && retained < 180);
        QVERIFY(window.retainedEstimatedBytes() <= 64 * 1024 * 1024);
        window.selectPacket(0);
        QVERIFY(waitForDetails(window));
        const auto first = window.packetModel()->packetAt(0);
        std::weak_ptr<const Packet> released = window.packetModel()->packetAt(1);
        const auto path = dir.filePath("saved.pcap");
        QSignalSpy done(&window, &MainWindow::saveFinished);
        QVERIFY(window.saveFile(path));
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 1000);
        auto *exporter = window.findChild<ExportEngine *>();
        QVERIFY(exporter->referencedBytes() > 0);
        window.packetModel()->clear();
        QVERIFY(!released.expired());
        gate->release();
        QTRY_COMPARE_WITH_TIMEOUT(done.count(), 1, 5000);
        QVERIFY(done.front()[0].toBool());
        QCOMPARE(done.front()[2].toInt(), retained);
        QCOMPARE(exporter->referencedBytes(), std::size_t(0));
        QVERIFY(released.expired());
        PcapReader reader(std::filesystem::path(path.toStdWString()));
        for (int i = 0; i < retained; ++i) {
            auto packet = reader.next();
            QVERIFY(packet && packet->bytes == raw.bytes);
        }
        QVERIFY(!reader.next());
        QCOMPARE(window.findChild<QLabel *>("detailProtocol")->text(), QString("ICMPv6"));
        QVERIFY(window.findChild<QLabel *>("detailCaptured")
                    ->text()
                    .contains(QString::number(first->raw.bytes.size())));
        for (const auto *key : {"capturedCount", "displayedCount", "droppedCount", "detailPacketId",
                                "detailProtocol", "detailCaptured", "detailOriginal"}) {
            const auto text = window.findChild<QLabel *>(key)->text();
            for (const auto ch : {QChar(0x00b7), QChar(0x2014), QChar(0x2013), QChar(0xff5c)})
                QVERIFY(!text.contains(ch));
        }
    }
    void denseQueueBudgetAndFileBackpressure() {
        std::vector<std::uint8_t> payload(24, 0);
        payload[0] = 135;
        for (int i = 0; i < 8000; ++i)
            payload.insert(payload.end(), {99, 1, 0, 0, 0, 0, 0, 0});
        const auto raw = fixtures::ipv6(58, payload, 255);
        auto hooks = fakeCapture();
        hooks.run = [raw](const QString &, bool, std::stop_token stop,
                          const CaptureHooks::Sink &sink, const CaptureHooks::Opened &opened,
                          const LiveCaptureOptions &) {
            opened("捕获中");
            for (int i = 0; i < 160 && !stop.stop_requested(); ++i)
                sink(raw);
            while (!stop.stop_requested())
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        };
        CaptureEngine live(nullptr, hooks);
        live.startLive("fake-a");
        QTRY_COMPARE_WITH_TIMEOUT(live.counters().received, std::uint64_t(160), 5000);
        live.stop();
        const auto counts = live.counters();
        QVERIFY(counts.enqueued > 0 && counts.enqueued < 160);
        QCOMPARE(counts.received, counts.enqueued + counts.queueDropped);
        QVERIFY(counts.peakQueuedEstimatedBytes <= 32 * 1024 * 1024);
        QVERIFY(counts.peakQueuedBytes < 8 * 1024 * 1024);
        auto records = live.takeBatch();
        QCOMPARE(records.size(), static_cast<std::size_t>(counts.enqueued));
        for (const auto &packet : records)
            QCOMPARE(packet.raw.bytes, raw.bytes);
        QCOMPARE(live.counters().queuedEstimatedBytes, std::uint64_t(0));
        records.clear();
        QTemporaryDir dir;
        const auto path = dir.filePath("dense.pcap");
        const auto decoded = decodePacket(raw);
        std::vector<const Packet *> refs(160, &decoded);
        {
            std::ofstream file(std::filesystem::path(path.toStdWString()), std::ios::binary);
            writePcap(file, refs);
        }
        CaptureEngine file;
        file.startFile(path);
        QTest::qWait(250);
        QVERIFY(file.running());
        QVERIFY(file.counters().queuedPackets < 160);
        QCOMPARE(file.counters().queueDropped, std::uint64_t(0));
        QElapsedTimer elapsed;
        elapsed.start();
        file.requestStop();
        QTRY_VERIFY_WITH_TIMEOUT(!file.running(), 1000);
        file.stop();
        QVERIFY(elapsed.elapsed() < 1000);
        file.takeBatch();
        QCOMPARE(file.counters().queuedEstimatedBytes, std::uint64_t(0));
        file.startFile(path);
        std::size_t read = 0;
        elapsed.restart();
        while ((file.running() || file.counters().queuedPackets) && elapsed.elapsed() < 10000) {
            auto batch = file.takeBatch(4);
            for (const auto &packet : batch)
                QCOMPARE(packet.raw.bytes, raw.bytes);
            read += batch.size();
            QTest::qWait(2);
        }
        file.stop();
        QCOMPARE(read, std::size_t(160));
        QCOMPARE(file.counters().queueDropped, std::uint64_t(0));
        QVERIFY(file.counters().peakQueuedEstimatedBytes <= 32 * 1024 * 1024);
    }
    void staleFilePreparationReply() {
        QTemporaryDir dir;
        const auto path = sampleFile(dir);
        auto gate = std::make_shared<Gate>();
        auto options = testOptions();
        options.prepareFile = [gate](const QString &path, std::stop_token) {
            gate->wait();
            return std::make_shared<PcapReader>(std::filesystem::path(path.toStdWString()));
        };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        ReleaseGate release{gate};
        window.show();
        QSignalSpy finished(&window, &MainWindow::fileOpenFinished);
        QVERIFY(window.openFile(path));
        QTRY_VERIFY_WITH_TIMEOUT(gate->entered.load(), 1000);
        auto *service = window.findChild<PreparationService *>();
        emit service->fileReady(service->fileGeneration() - 1, path, {}, "过期错误", false);
        QTest::qWait(20);
        QCOMPARE(finished.count(), 0);
        QVERIFY(window.busy());
        QVERIFY(!window.findChild<QLabel *>("captureStatus")->text().contains("过期"));
        gate->release();
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 3000);
        const auto old = finished.front()[0].toULongLong();
        QCOMPARE(finished.front()[1].value<MainWindow::FileOpenResult>(),
                 MainWindow::FileOpenResult::Success);
        QVERIFY(window.openFile(path));
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 2, 3000);
        QVERIFY(finished.back()[0].toULongLong() > old);
        QCOMPARE(finished.back()[1].value<MainWindow::FileOpenResult>(),
                 MainWindow::FileOpenResult::Success);
    }
    void interfaceColumnsAndGeneratedText() {
        auto options = testOptions();
        options.capture = fakeCapture();
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        window.show();
        auto *selector = window.findChild<QComboBox *>("deviceSelector");
        QCOMPARE(selector->model()->columnCount(), 2);
        QCOMPARE(selector->model()->headerData(0, Qt::Horizontal).toString(), QString("名称"));
        QCOMPARE(selector->model()->headerData(1, Qt::Horizontal).toString(), QString("地址"));
        selector->showPopup();
        QTest::qWait(20);
        const auto addressIndex = selector->model()->index(1, 1);
        auto *view = selector->view();
        QVERIFY(view->visualRect(addressIndex).isValid());
        QTest::mouseClick(view->viewport(), Qt::LeftButton, Qt::NoModifier,
                          view->visualRect(addressIndex).center());
        QCOMPARE(selector->currentData().toString(), QString("fake-b"));
        const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
        if (!screenshots.isEmpty()) {
            selector->showPopup();
            QTest::qWait(20);
            QVERIFY(view->window()->grab().save(screenshots + "/interfaces.png"));
            selector->hidePopup();
        }
        for (const auto &raw : fixtures::samples()) {
            const auto packet = decodePacket(raw);
            for (const auto ch :
                 {std::string("·"), std::string("—"), std::string("–"), std::string("｜")})
                QVERIFY(packet.summary.find(ch) == std::string::npos);
        }
        for (auto raw : fixtures::ipv6Samples()) {
            const auto packet = decodePacket(std::move(raw));
            auto scan = [](auto &&self, const std::vector<Field> &fields) -> bool {
                for (const auto &field : fields) {
                    for (const auto &ch :
                         {std::string("·"), std::string("—"), std::string("–"), std::string("｜")})
                        if (field.value.find(ch) != std::string::npos)
                            return false;
                    if (!self(self, field.children))
                        return false;
                }
                return true;
            };
            QVERIFY(scan(scan, packet.fields));
        }
    }
    void stopAfterPreparationBeforeQueuedDelivery() {
        QTemporaryDir dir;
        const auto path = sampleFile(dir);
        MainWindow window(nullptr, testOptions());
        QVERIFY(waitForInterfaces(window));
        window.show();
        QSignalSpy finished(&window, &MainWindow::fileOpenFinished);
        QVERIFY(window.openFile(path));
        auto *service = window.findChild<PreparationService *>();
        QElapsedTimer deadline;
        deadline.start();
        while (service->preparingFile() && deadline.elapsed() < 3000)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        QVERIFY(!service->preparingFile());
        window.stopCapture();
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 3000);
        QCOMPARE(finished.front()[1].value<MainWindow::FileOpenResult>(),
                 MainWindow::FileOpenResult::Cancelled);
        QCOMPARE(window.packetModel()->rowCount(), 0);
        QVERIFY(!window.busy());
    }
    void missingDriverKeepsOfflineAnalysisAvailable() {
        auto available = std::make_shared<bool>(false);
        auto options = testOptions();
        options.capture = fakeCapture();
        options.capture.interfaces = [available](QString &error) {
            if (!*available) {
                error = "Npcap 未安装";
                return std::vector<CaptureInterface>{};
            }
            error.clear();
            return std::vector<CaptureInterface>{{"fake-a", "测试网卡", "192.0.2.1"}};
        };
        MainWindow window(nullptr, options);
        QVERIFY(waitForInterfaces(window));
        window.show();
        QCOMPARE(window.findChild<QLabel *>("captureStatus")->text(), QString("Npcap 未安装"));
        QVERIFY(!window.findChild<QPushButton *>("startButton")->isEnabled());
        QTemporaryDir directory;
        QVERIFY(window.openFile(sampleFile(directory)));
        QTRY_VERIFY_WITH_TIMEOUT(!window.busy(), 5000);
        QCOMPARE(window.packetModel()->rowCount(), 12);
        *available = true;
        window.findChild<QAction *>("refreshAction")->trigger();
        QVERIFY(waitForInterfaces(window));
        QVERIFY(window.findChild<QPushButton *>("startButton")->isEnabled());
        QVERIFY(!window.busy());
    }
};
QTEST_MAIN(DesktopTests)
#include "ui_tests.moc"
