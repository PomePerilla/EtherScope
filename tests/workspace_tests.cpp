#include "ui/main_window.h"
#include "ui/application_view.h"
#include "ui/find_bar.h"
#include "ui/reading_history.h"
#include "ui/language.h"
#include "fixtures.h"
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDockWidget>
#include <QDir>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QSignalSpy>
#include <QShortcut>
#include <QTableView>
#include <QTemporaryDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QVBoxLayout>
#include <QTest>
#include <QTreeWidget>
using namespace etherscope;
namespace {
MainWindowOptions options() {
    static QTemporaryDir dir;
    static int id{};
    MainWindowOptions result;
    result.settingsFile = dir.filePath(QString::number(++id) + ".ini");
    result.capture.interfaces = [](QString &) {
        return std::vector<CaptureInterface>{{"test", "Test", "192.0.2.1"}};
    };
    return result;
}
std::shared_ptr<ApplicationResult> result(bool revised = false) {
    auto r = std::make_shared<ApplicationResult>();
    auto bytes = std::make_shared<std::vector<std::uint8_t>>(10000, 'x');
    const auto needle = QByteArray::fromHex("0123456789abcdef");
    std::copy(needle.begin(), needle.end(), bytes->begin() + 5000);
    for (unsigned n = 0; n < 20; ++n) {
        ApplicationMessage m;
        m.protocol = "HTTP";
        m.summary = n == 12 ? "needle.example" : "other.example";
        m.source = DataSource::Reassembled;
        m.streamOffset = n * 10000;
        m.bytes = bytes;
        m.length = bytes->size();
        m.sources = {{n + 1, 0, bytes->size(), 0}};
        m.fields = {
            {"Host", "http.host", std::string(n == 12 ? "needle.example" : "other.example"), 0, 8},
            {"Method", "http.method", std::string(revised ? "POST" : "GET"), 5000, 8}};
        r->messages.push_back(std::move(m));
    }
    return r;
}
} // namespace
class WorkspaceTests final : public QObject {
    Q_OBJECT
  private:
    void search(FindBar *bar, int scope, const QString &query, bool hex = false) {
        bar->show();
        bar->findChild<QComboBox *>("findScope")->setCurrentIndex(scope);
        bar->findChild<QComboBox *>("findMode")->setCurrentIndex(hex ? 1 : 0);
        bar->findChild<QLineEdit *>("findInput")->setText(query);
        bar->findChild<QPushButton *>("findRefresh")->click();
        QTRY_VERIFY_WITH_TIMEOUT(!bar->searching(), 5000);
    }
  private slots:
    void historyIsBoundedAndBranches() {
        ReadingHistory history;
        for (int i = 0; i < 75; ++i)
            history.remember({{"id", i}});
        for (int i = 74; i >= 25; --i)
            QCOMPARE(history.take(false, {{"id", i + 1}})["id"].toInt(), i);
        QVERIFY(!history.canBack());
        QVERIFY(history.canForward());
        history.remember({{"id", 100}});
        QVERIFY(!history.canForward());
        history.clear();
        QVERIFY(!history.canBack());
    }
    void searchSnapshotsAndInvalidates() {
        QWidget parent;
        FindBar bar(&parent);
        bool valid = true;
        QString located;
        const auto snapshot = std::make_shared<std::vector<FindDocument>>(
            10000, FindDocument{"stable", "IPv6 2001:db8::1", {}});
        bar.addTarget({"Rows", &parent, false,
                       [&] {
                           return FindSource{
                               int(snapshot->size()),
                               [snapshot](int n) { return (*snapshot)[std::size_t(n)]; },
                               [&] { return valid; }};
                       },
                       [&](const QString &key, std::size_t, std::size_t) {
                           located = key;
                           return true;
                       }});
        search(&bar, 0, "2001:DB8::1");
        QVERIFY(bar.findChild<QPushButton *>("findNext")->isEnabled());
        bar.findChild<QPushButton *>("findNext")->click();
        QCOMPARE(located, "stable");
        valid = false;
        located.clear();
        bar.findChild<QPushButton *>("findNext")->click();
        QVERIFY(located.isEmpty());
        QVERIFY(!bar.findChild<QPushButton *>("findNext")->isEnabled());
        bar.invalidate();
        QVERIFY(!bar.searching());
    }
    void byteSearchAcrossPagesAndInvalidInput() {
        MainWindow window(nullptr, options());
        window.show();
        auto raw = fixtures::icmp();
        raw.bytes.resize(10000, 0);
        raw.originalLength = 10000;
        const auto needle = QString::fromUtf8("网络").toUtf8();
        std::copy(needle.begin(), needle.end(), raw.bytes.begin() + 5000);
        window.ingestBenchmark({decodeSummary(raw)});
        window.selectPacket(0);
        auto *bar = window.findChild<FindBar *>();
        search(bar, 2, QString::fromUtf8("网络"));
        bar->findChild<QPushButton *>("findNext")->click();
        QVERIFY(window.findChild<QPlainTextEdit *>("hexView")->toPlainText().startsWith("001000"));
        QVERIFY(!window.findChild<QPlainTextEdit *>("hexView")->extraSelections().empty());
        search(bar, 2, "e7 bd 91 e7 bb 9c", true);
        QVERIFY(bar->findChild<QPushButton *>("findNext")->isEnabled());
        search(bar, 2, "0xz", true);
        QVERIFY(!bar->findChild<QPushButton *>("findNext")->isEnabled());
        QVERIFY(bar->findChild<QLabel *>("findStatus")->text().contains("08 00"));
        window.close();
    }
    void packetSearchHistoryAndSourceReset() {
        MainWindow window(nullptr, options());
        window.show();
        auto raw = fixtures::icmp();
        auto other = raw;
        other.bytes[29] = 77;
        window.ingestBenchmark({decodeSummary(raw), decodeSummary(other)});
        window.selectPacket(0);
        QTRY_VERIFY(!window.detailsBusy());
        auto *bar = window.findChild<FindBar *>();
        search(bar, 0, "192.0.2.77");
        bar->findChild<QPushButton *>("findNext")->click();
        auto *table = window.findChild<QTableView *>("packetTable");
        QCOMPARE(table->currentIndex().row(), 1);
        window.findChild<QAction *>("readingBack")->trigger();
        QTRY_VERIFY(!window.detailsBusy());
        QCOMPARE(table->currentIndex().row(), 0);
        window.findChild<QAction *>("readingForward")->trigger();
        QTRY_VERIFY(!window.detailsBusy());
        QCOMPARE(table->currentIndex().row(), 1);
        QVERIFY(window.applyExpression("icmp.type == 8"));
        QVERIFY(!bar->findChild<QPushButton *>("findNext")->isEnabled());
        window.close();
    }
    void hiddenColumnsDoNotMatch() {
        MainWindow window(nullptr, options());
        window.show();
        window.ingestBenchmark({decodeSummary(fixtures::icmp())});
        auto *table = window.findChild<QTableView *>("packetTable");
        table->setColumnHidden(2, true);
        auto *bar = window.findChild<FindBar *>();
        const auto source =
            window.packetModel()->data(window.packetModel()->index(0, 2)).toString();
        search(bar, 0, source);
        QVERIFY(!bar->findChild<QPushButton *>("findNext")->isEnabled());
        table->setColumnHidden(2, false);
        search(bar, 0, source);
        QVERIFY(bar->findChild<QPushButton *>("findNext")->isEnabled());
        window.close();
    }
    void applicationSearchHistoryAndRefresh() {
        MainWindow owner(nullptr, options());
        ApplicationView view;
        view.resize(1000, 760);
        view.show();
        view.setBinding({0, 1, 1}, ApplicationView::Scope::Conversation, 1);
        view.setResults({result()});
        QTRY_VERIFY(!view.updating());
        auto *messages = view.findChild<QTreeWidget *>("applicationMessages");
        auto *fields = view.findChild<QTreeWidget *>("applicationFields");
        auto *bar = view.findChild<FindBar *>();
        search(bar, 0, "needle.example");
        bar->findChild<QPushButton *>("findNext")->click();
        QTRY_VERIFY(!view.updating());
        QCOMPARE(messages->indexOfTopLevelItem(messages->currentItem()), 12);
        search(bar, 1, "GET");
        bar->findChild<QPushButton *>("findNext")->click();
        QCOMPARE(fields->currentItem()->data(0, Qt::UserRole + 5).toString(), "http.method");
        view.findChild<QPushButton *>("applicationPreviousPage")->click();
        search(bar, 2, "01 23 45 67 89 ab cd ef", true);
        bar->findChild<QPushButton *>("findNext")->click();
        QVERIFY(view.findChild<QPlainTextEdit *>("applicationBytes")
                    ->toPlainText()
                    .startsWith("001000"));
        const auto screenshot = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
        if (!screenshot.isEmpty())
            QVERIFY(view.grab().save(screenshot + "/application-find.png"));
        view.findChild<QPushButton *>("applicationReadingBack")->click();
        QTRY_VERIFY(!view.updating());
        QVERIFY(view.findChild<QPlainTextEdit *>("applicationBytes")
                    ->toPlainText()
                    .startsWith("000000"));
        const auto key = messages->currentItem()->data(0, Qt::UserRole + 7);
        view.setResults({result(true)});
        QTRY_VERIFY(!view.updating());
        QCOMPARE(messages->currentItem()->data(0, Qt::UserRole + 7), key);
        view.findChild<QPushButton *>("applicationReadingBack")->click();
        QTRY_VERIFY(!view.updating());
        view.findChild<QPushButton *>("applicationReadingBack")->click();
        QTRY_VERIFY(!view.updating());
        QCOMPARE(messages->indexOfTopLevelItem(messages->currentItem()), 0);
        view.setBinding({0, 2, 1}, ApplicationView::Scope::Conversation, 1);
        QVERIFY(!view.findChild<QPushButton *>("applicationReadingBack")->isEnabled());
        QVERIFY(!bar->findChild<QPushButton *>("findNext")->isEnabled());
        view.close();
    }
    void keyboardRoutesToFocusedPanel() {
        MainWindow window(nullptr, options());
        window.show();
        window.ingestBenchmark({decodeSummary(fixtures::icmp())});
        auto *table = window.findChild<QTableView *>("packetTable");
        table->setFocus();
        QTest::qWait(20);
        QTest::keyClick(table, Qt::Key_F, Qt::ControlModifier);
        auto *bar = window.findChild<FindBar *>();
        QTRY_VERIFY(!bar->isHidden());
        QTest::keyClick(bar->findChild<QLineEdit *>("findInput"), Qt::Key_Escape);
        QVERIFY(bar->isHidden());
        window.close();
    }
    void nestedAnalysisOwnsKeyboardFind() {
        MainWindow window(nullptr, options());
        window.show();
        auto *view = new ApplicationView(window.centralWidget());
        window.centralWidget()->layout()->addWidget(view);
        view->setBinding({0, 1, 1}, ApplicationView::Scope::Packet, 1);
        view->setResults({result()});
        QTRY_VERIFY(!view->updating());
        auto *messages = view->findChild<QTreeWidget *>("applicationMessages");
        window.activateWindow();
        messages->setFocus();
        QTest::qWait(20);
        QTest::keyClick(messages, Qt::Key_F, Qt::ControlModifier);
        QTRY_VERIFY(!view->findChild<FindBar *>("applicationFindBar")->isHidden());
        QVERIFY(window.findChild<FindBar *>("mainFindBar")->isHidden());
        window.close();
    }
    void escapeClosesFindBeforeParentPanel() {
        QWidget panel;
        auto *layout = new QVBoxLayout(&panel);
        auto *tree = new QTreeWidget(&panel);
        layout->addWidget(tree);
        auto *find = new FindBar(&panel);
        layout->addWidget(find);
        find->addTarget({"Rows", tree, false, [] { return FindSource{}; },
                         [](const QString &, std::size_t, std::size_t) { return false; }});
        bool parentClosed = false;
        QShortcut escape(QKeySequence(Qt::Key_Escape), &panel);
        escape.setContext(Qt::WidgetWithChildrenShortcut);
        connect(&escape, &QShortcut::activated, &panel, [&] { parentClosed = true; });
        panel.show();
        panel.activateWindow();
        find->openFor(tree);
        QTest::qWait(20);
        QTest::keyClick(find->findChild<QLineEdit *>("findInput"), Qt::Key_Escape);
        QVERIFY(find->isHidden());
        QVERIFY(!parentClosed);
        find->openFor(tree);
        search(find, 0, "empty");
        QCOMPARE(find->findChild<QLabel *>("findStatus")->text(),
                 i18n::text("%1 / %2 项").arg(0).arg(0));
    }
    void backgroundAnalysisKeepsCurrentCell() {
        MainWindow window(nullptr, options());
        window.show();
        window.ingestBenchmark(
            {decodeSummary(fixtures::tcp(24, 100, 0, false, 50000, true, {'x'}))});
        auto *table = window.findChild<QTableView *>("packetTable");
        table->setCurrentIndex(window.packetModel()->index(0, 2));
        QTest::qWait(250);
        QCOMPARE(table->currentIndex().column(), 2);
        window.close();
    }
    void diagnosticsPreservesMinimumWindow_data() {
        QTest::addColumn<QSize>("size");
        QTest::newRow("small") << QSize(900, 580);
        QTest::newRow("medium") << QSize(1024, 768);
        QTest::newRow("large") << QSize(1440, 900);
    }
    void diagnosticsPreservesMinimumWindow() {
        QFETCH(QSize, size);
        MainWindow window(nullptr, options());
        window.resize(size);
        window.show();
        window.findChild<QPushButton *>("diagnosticsToggle")->click();
        QTest::qWait(20);
        auto *dock = window.findChild<QDockWidget *>("diagnosticDock");
        QVERIFY(dock->isVisible());
        QVERIFY(window.minimumWidth() <= 900);
        QVERIFY(window.minimumHeight() <= 580);
        if (size.width() < 1280)
            QVERIFY(dock->isFloating());
        const auto output = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
        if (!output.isEmpty()) {
            QDir().mkpath(output);
            QVERIFY(window.grab().save(output + QString("/diagnostics-%1.png").arg(size.width())));
            if (dock->isFloating())
                QVERIFY(dock->grab().save(
                    output + QString("/diagnostic-floating-%1.png").arg(size.width())));
        }
        dock->close();
        QVERIFY(!window.findChild<QPushButton *>("diagnosticsToggle")->isChecked());
        window.close();
    }
    void courseEthernetIpIcmpAndFilters() {
        auto config = options();
        config.language = "zh_CN";
        MainWindow window(nullptr, config);
        window.show();
        for (auto type : {8, 0, 11, 3})
            window.ingestBenchmark(
                {decodeSummary(fixtures::icmp(std::uint8_t(type), type == 3 ? 3 : 0))});
        QCOMPARE(window.packetModel()->rowCount(), 4);
        auto *fields = window.findChild<QTreeWidget *>("fieldTree");
        QVERIFY(fields);
        QJsonArray icmp;
        const auto screenshots = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
        for (int n = 0; n < 4; ++n) {
            window.selectPacket(n);
            QTRY_VERIFY(!window.detailsBusy());
            QTreeWidgetItem *ethernet = nullptr, *ip = nullptr, *control = nullptr;
            for (QTreeWidgetItemIterator it(fields); *it; ++it) {
                const auto name = (*it)->data(0, Qt::UserRole + 3).toString();
                if (name == "Ethernet II")
                    ethernet = *it;
                if (name == "IPv4")
                    ip = *it;
                if (name == "ICMP")
                    control = *it;
            }
            QVERIFY(ethernet);
            QVERIFY(ip);
            QVERIFY(control);
            QVERIFY(ethernet->childCount() >= 3);
            QVERIFY(ip->childCount() >= 13);
            QVERIFY(control->childCount() >= 5);
            const auto packet = window.packetModel()->packetAt(n);
            QVERIFY(packet->error.empty());
            icmp.append(QString::fromStdString(packet->summary));
            if (!screenshots.isEmpty())
                QVERIFY(window.grab().save(screenshots +
                                           QString("/course-icmp-%1.png").arg(*packet->icmpType)));
        }
        auto *mac = window.findChild<QLineEdit *>("macInput");
        auto *ip = window.findChild<QLineEdit *>("ipInput");
        QVERIFY(mac);
        QVERIFY(ip);
        const auto packet = window.packetModel()->packetAt(0);
        mac->setText(QString::fromStdString(formatMac(*packet->sourceMac)));
        ip->setText(QString::fromStdString(formatIp(*packet->sourceIp)));
        window.findChild<QPushButton *>("applyFilterButton")->click();
        QCOMPARE(window.packetModel()->rowCount(), 4);
        ip->setText("203.0.113.254");
        window.findChild<QPushButton *>("applyFilterButton")->click();
        QCOMPARE(window.packetModel()->rowCount(), 0);
        ip->setText("invalid");
        window.findChild<QPushButton *>("applyFilterButton")->click();
        QCOMPARE(window.packetModel()->rowCount(), 0);
        const auto output = qEnvironmentVariable("ETHERSCOPE_COURSE_REPORT");
        if (!output.isEmpty()) {
            QFile file(output);
            QVERIFY(file.open(QIODevice::WriteOnly));
            file.write(
                QJsonDocument(QJsonObject{{"ethernet_fields", true},
                                          {"ipv4_fields", true},
                                          {"icmp", icmp},
                                          {"mac_and_ip_filters", true},
                                          {"invalid_filter_preserves_applied_condition", true},
                                          {"input", "constructed Ethernet IPv4 fixtures"}})
                    .toJson());
        }
        window.close();
    }
    void workspaceVisualMatrix() {
        for (const auto &language : {"zh_CN", "zh_TW", "en"})
            for (bool dark : {false, true})
                for (const auto size : {QSize(900, 580), QSize(1024, 768), QSize(1440, 900)}) {
                    auto config = options();
                    config.language = language;
                    MainWindow window(nullptr, config);
                    window.setDarkTheme(dark);
                    window.resize(size);
                    window.show();
                    window.ingestBenchmark({decodeSummary(fixtures::icmp())});
                    window.selectPacket(0);
                    QTRY_VERIFY(!window.detailsBusy());
                    auto *bar = window.findChild<FindBar *>();
                    search(bar, 0, "192.0.2");
                    auto *table = window.findChild<QTableView *>("packetTable");
                    QVERIFY(window.rect().contains(
                        QRect(table->mapTo(&window, QPoint()), table->size())));
                    for (auto *widget :
                         bar->findChildren<QWidget *>(QString(), Qt::FindDirectChildrenOnly))
                        if (widget->isVisible())
                            QTRY_VERIFY2(bar->rect().contains(widget->geometry()),
                                         qPrintable(widget->objectName()));
                    const auto output = qEnvironmentVariable("ETHERSCOPE_SCREENSHOTS");
                    if (!output.isEmpty())
                        QVERIFY(window.grab().save(output + QString("/find-%1-%2-%3.png")
                                                                .arg(language)
                                                                .arg(dark ? "dark" : "light")
                                                                .arg(size.width())));
                    window.close();
                }
    }
};
QTEST_MAIN(WorkspaceTests)
#include "workspace_tests.moc"
