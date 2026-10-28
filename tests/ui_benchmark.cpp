#include "ui/main_window.h"
#include "ui/find_bar.h"
#include <QLineEdit>
#include "ui/analysis_dock.h"
#include "ui/application_view.h"
#include <QTreeWidget>
#include <QTabWidget>
#include <QMenu>
#include <QTableView>
#include "ui/tcp_dialog.h"
#include "ui/stream_pane.h"
#include "ui/language.h"
#include "fixtures.h"
#include "benchmark_metrics.h"
#include "core/pcap_file.h"
#include "version.h"
#include <QApplication>
#include <QCheckBox>
#include <QAction>
#include <QComboBox>
#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPushButton>
#include <QTemporaryDir>
#include <QStyleFactory>
#include <QSettings>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <future>
#include <QFontDatabase>
#include <thread>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#endif

namespace {
using namespace etherscope;
constexpr std::int64_t timestampBase = 1700000000000000000LL;
std::uint64_t resident() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX memory{};
    memory.cb = sizeof(memory);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&memory), sizeof(memory)))
        return memory.PrivateUsage;
#endif
    return 0;
}
double cpuSeconds() {
#ifdef _WIN32
    FILETIME created, exited, kernel, user;
    if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) {
        const auto ticks = [](FILETIME value) {
            return (std::uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime;
        };
        return double(ticks(kernel) + ticks(user)) / 10000000.0;
    }
#endif
    return 0;
}
qint64 percentile(std::vector<qint64> values, int percent) {
    if (values.empty())
        return 0;
    std::sort(values.begin(), values.end());
    return values[std::min(values.size() - 1, values.size() * percent / 100)];
}
} // namespace
int main(int argc, char **argv) {
    using namespace etherscope;
    QApplication app(argc, argv);
    app.setApplicationVersion(ETHERSCOPE_VERSION);
    app.setStyle(QStyleFactory::create("Fusion"));
    app.setFont(QFont("Microsoft YaHei UI", 10));
    if (QGuiApplication::platformName() == "offscreen") {
        const auto fonts = qEnvironmentVariable("WINDIR") + "/Fonts/";
        QFontDatabase::addApplicationFont(fonts + "msyh.ttc");
        QFontDatabase::addApplicationFont(fonts + "consola.ttf");
        QFontDatabase::addApplicationFont(fonts + "segoeui.ttf");
    }
    int seconds = 600, pps = 1000;
    QString output = "ui-benchmark.json";
    const auto args = app.arguments();
    for (int i = 1; i + 1 < args.size(); ++i) {
        if (args[i] == "--seconds")
            seconds = args[++i].toInt();
        else if (args[i] == "--pps")
            pps = args[++i].toInt();
        else if (args[i] == "--output")
            output = args[++i];
    }
    if (seconds < 2 || seconds > 7200 || pps < 1 || pps > 100000)
        return 2;
    auto raws = fixtures::samples();
    const auto ipv6 = fixtures::ipv6Samples();
    raws.insert(raws.end(), ipv6.begin(), ipv6.end());
    const auto analysis = fixtures::analysisSamples();
    raws.insert(raws.end(), analysis.begin(), analysis.end());
    if (args.contains("--tcp"))
        raws = fixtures::tcpConversationSamples();
    if (const auto position = args.indexOf("--application-pcap");
        position >= 0 && position + 1 < args.size()) {
        CaptureReader reader(std::filesystem::path(args[position + 1].toStdWString()));
        raws.clear();
        while (auto raw = reader.next())
            raws.push_back(std::move(*raw));
        if (raws.empty())
            return 2;
    }
    const bool longHttp = args.contains("--long-http");
    const bool applicationViewLoad = args.contains("--application-view");
    const std::string longRequest = "GET /keep HTTP/1.1\r\nHost: persistent.example\r\n\r\n";
    const std::string largeRequest = "GET /keep HTTP/1.1\r\nHost: persistent.example\r\nX-Padding: " + std::string(6000, 'p') + "\r\n\r\n";
    std::uint64_t largePeriod = 100;
    const auto periodArgument = args.indexOf("--large-period");
    if (periodArgument >= 0 && periodArgument + 1 < args.size()) {
        bool valid = false; largePeriod = args[periodArgument + 1].toULongLong(&valid);
        if (!valid || !largePeriod || largePeriod > 100000) return 2;
    }
    const auto extraRequestBytes = applicationViewLoad ? largeRequest.size() - longRequest.size() : 0;
    const std::string longResponse = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    if (longHttp)
        raws = {fixtures::tcp(2, 99), fixtures::tcp(18, 499, 100, true),
                fixtures::tcp(16, 100, 500),
                fixtures::tcp(24, 100, 500, false, 50000, false,
                              {longRequest.begin(), longRequest.end()}),
                fixtures::tcp(24, 500, 100, true, 50000, false,
                              {longResponse.begin(), longResponse.end()})};
    if (longHttp && applicationViewLoad)
        raws.push_back(fixtures::tcp(24, 100, 500, false, 50000, false, {largeRequest.begin(), largeRequest.end()}));
    const bool streamLoad = args.contains("--stream-load");
    if (streamLoad)
        raws = {
            fixtures::tcp(24, 100, 0, false, 50000, false, std::vector<std::uint8_t>(1024, 'x'))};
    for (auto &raw : raws) {
        raw.bytes.resize(std::max<std::size_t>(64, raw.bytes.size()), 0);
        raw.originalLength = static_cast<std::uint32_t>(raw.bytes.size());
    }
    const auto target = std::uint64_t(seconds) * pps;
    auto rawAt = [&](std::uint64_t index) {
        auto raw = raws[longHttp ? (index < 3 ? index :
            (applicationViewLoad && (index-3)%2==0 && ((index-3)/2)%largePeriod==0 ? 5 : 3+(index-3)%2)) : index % raws.size()];
        raw.timestampNs = timestampBase + static_cast<std::int64_t>(index) * 1000000;
        auto write = [&](std::size_t offset, std::uint32_t value) {
            for (unsigned byte = 0; byte < 4; ++byte)
                raw.bytes[offset + byte] = static_cast<std::uint8_t>(value >> (24 - 8 * byte));
        };
        if (streamLoad)
            write(38, static_cast<std::uint32_t>(index * 1024 + 100));
        if (longHttp && index >= 3) {
            const auto round = (index - 3) / 2;
            const bool response = (index - 3) % 2;
            write(38, static_cast<std::uint32_t>(
                          (response ? 500 : 100) +
                          round * (response ? longResponse.size() : longRequest.size()) +
                          (response ? 0 : (round+largePeriod-1)/largePeriod*extraRequestBytes)));

            write(42, static_cast<std::uint32_t>(response ? 100 + (round + 1) * longRequest.size() +
                              (round+largePeriod)/largePeriod*extraRequestBytes : 500 + round * longResponse.size()));
        }
        return raw;
    };
    MainWindowOptions options;
    QTemporaryDir temporary;
    options.settingsFile = temporary.filePath("settings.ini");
    const bool languageCycle = args.contains("--language-cycle");
    options.language = languageCycle ? "en" : "zh_CN";
    options.capture.interfaces = [](QString &error) {
        error.clear();
        return std::vector<CaptureInterface>{{"benchmark", "性能测试", "192.0.2.1"}};
    };
    options.capture.run = [&](const QString &, bool, std::stop_token stop,
                              const CaptureHooks::Sink &sink, const CaptureHooks::Opened &opened,
                              const LiveCaptureOptions &) {
        opened("捕获中");
        const auto start = std::chrono::steady_clock::now();
        std::uint64_t sent = 0;
        while (!stop.stop_requested()) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                                     std::chrono::steady_clock::now() - start)
                                     .count();
            const auto due = std::min(target, std::uint64_t(elapsed) * pps / 1000000);
            while (sent < due && !stop.stop_requested()) {
                auto raw = rawAt(sent);
                sink(std::move(raw));
                ++sent;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    };
    struct ExpectedExport {
        std::uint64_t count;
        std::int64_t first, last;
    };
    std::deque<ExpectedExport> expectedExports;
    options.snapshotObserver = [&](const PacketSnapshot &snapshot) {
        expectedExports.push_back(
            {snapshot.size(), snapshot.front()->raw.timestampNs, snapshot.back()->raw.timestampNs});
    };
    std::size_t expectedRetained = 0, expectedRaw = 0, expectedBytes = 0;
    for (auto id = target; id > 0 && expectedRetained < 10000; --id) {
        auto raw = rawAt(id - 1);
        const auto rawBytes = raw.bytes.size(), cost = decodeSummary(std::move(raw)).estimatedBytes;
        if (expectedRaw + rawBytes > 64 * 1024 * 1024 || expectedBytes + cost > 64 * 1024 * 1024)
            break;
        ++expectedRetained;
        expectedRaw += rawBytes;
        expectedBytes += cost;
    }
    const auto payloadRecords = target > 3 ? target - 3 : 0;
    const auto expectedDelivered =
        (payloadRecords + 1) / 2 * longRequest.size() + payloadRecords / 2 * longResponse.size() +
        (((payloadRecords+1)/2 + largePeriod-1)/largePeriod)*extraRequestBytes;
    const bool recordingLoad = args.contains("--recording");
    if (recordingLoad) {
        QSettings settings(options.settingsFile, QSettings::IniFormat);
        settings.setValue("recording/directory", temporary.filePath("recordings"));
        settings.setValue("recording/fileMiB", 16);
        settings.setValue("recording/diskMiB", 64);
        settings.sync();
    }
    MainWindow window(nullptr, options);
    window.resize(args.contains("--workspace-interactions") ? 1440 : 1280,
                  args.contains("--workspace-interactions") ? 900 : 820);
    window.show();
    const auto expression =
        args.contains("--application-filter") ? compileDisplayFilter("http.host").value : nullptr;
    if (expression)
        window.applyExpression(QString::fromStdString(expression->source()));
    if (const auto position = args.indexOf("--key-log");
        position >= 0 && position + 1 < args.size())
        window.setTlsKeyLog(args[position + 1]);
    if (recordingLoad)
        window.findChild<QAction *>("recordingAction")->setChecked(true);
    if (args.contains("--tcp-panel") || streamLoad || applicationViewLoad)
        window.findChild<QAction *>("tcpConversationsAction")->trigger();
    bool panelBound = false;
    int workspaceInteractions = 0;
    ApplicationView *visibleApplication = nullptr;
    QString observedApplicationRows;
    int applicationViewUpdates = 0, applicationPageClicks = 0;
    bool chooseApplicationField = false;
    qint64 nextWorkspaceInteraction = 5000;
    StreamPane *streamPane = nullptr;
    int streamRequests = 0, streamCompleted = 0;
    bool streamValid = true;
    qint64 nextStream = 2000;
    if (streamLoad) {
        streamPane = window.findChild<StreamPane *>();
        QObject::connect(streamPane, &StreamPane::analysisFinished, &app,
                         [&](quint64, bool success) {
                             streamValid = streamValid && success;
                             ++streamCompleted;
                         });
    }
    QElapsedTimer clock, stopClock;
    clock.start();
    const auto cpuStart = cpuSeconds();
    BoundedSamples delays, appendTimes, filterTimes;
    QJsonArray memorySamples;
    QJsonArray exports;
    QJsonArray stalls;
    QTimer poll;
    poll.setTimerType(Qt::PreciseTimer);
    qint64 lastBeat = 0, lastMemory = -1000, nextProgress = 60000;
    bool stopping = false, selected = false, theme = false, filtered = false, cleared = false,
         intentionalReset = false;
    qint64 captureStopMs = -1, recordingStopMs = -1;
    int resets = 0, saveRequests = 0, languageChanges = 0;
    int findInteractions = 0;
    bool findPending = false;
    std::uint64_t beforeFindPacket{};
    qint64 nextLanguage = 10000;
    bool saveValid = true;
    qint64 themeUs = 0;
    std::vector<std::future<QJsonObject>> validations;
    QObject::connect(window.packetModel(), &QAbstractItemModel::modelReset, &app, [&] {
        if (!intentionalReset && window.captureState() != MainWindow::CaptureState::Starting)
            ++resets;
    });
    QObject::connect(&window, &MainWindow::batchProcessed, &app,
                     [&](qint64 us) { appendTimes.push_back(us); });
    QObject::connect(
        &window, &MainWindow::saveFinished, &app,
        [&](bool success, const QString &path, quint64 count, const QString &error) {
            if (expectedExports.empty()) {
                saveValid = false;
                return;
            }
            const auto expected = expectedExports.front();
            expectedExports.pop_front();
            validations.push_back(
                std::async(std::launch::async, [&, success, path, count, error, expected] {
                    QElapsedTimer validation;
                    validation.start();
                    std::uint64_t records = 0;
                    std::int64_t previous = -1;
                    bool exact = success && count == expected.count;
                    try {
                        PcapReader reader(std::filesystem::path(path.toStdWString()));
                        while (auto raw = reader.next()) {
                            const auto sequence = (raw->timestampNs - timestampBase) / 1000000;
                            exact = exact && sequence >= 0 &&
                                    (previous < 0 || sequence == previous + 1) &&
                                    raw->timestampNs == timestampBase + sequence * 1000000 &&
                                    raw->bytes == rawAt(static_cast<std::uint64_t>(sequence)).bytes;
                            if (records == 0)
                                exact = exact && raw->timestampNs == expected.first;
                            previous = sequence;
                            ++records;
                        }
                    } catch (const std::exception &) {
                        exact = false;
                    }
                    exact = exact && records == expected.count &&
                            timestampBase + previous * 1000000 == expected.last;
                    return QJsonObject{{"success", success},
                                       {"exact_bytes_and_order", exact},
                                       {"count", double(count)},
                                       {"error", error},
                                       {"validation_us", double(validation.nsecsElapsed() / 1000)}};
                }));
        });
    auto applyProtocol = [&](const QString &value) {
        intentionalReset = true;
        QElapsedTimer timer;
        timer.start();
        auto *protocol = window.findChild<QComboBox *>("protocolFilter");
        if (value == "全部协议")
            protocol->setCurrentIndex(0);
        else
            protocol->setCurrentText(value);
        filterTimes.push_back(timer.nsecsElapsed() / 1000);
        intentionalReset = false;
    };
    QObject::connect(&poll, &QTimer::timeout, &app, [&] {
        const auto now = clock.elapsed();
        if (lastBeat) {
            const auto delay = std::max<qint64>(0, now - lastBeat - 20);
            delays.push_back(delay);
            if (delay > 50 && stalls.size() < 256)
                stalls.append(
                    QJsonObject{{"elapsed_ms", double(now)}, {"delay_ms", double(delay)}});
        }
        lastBeat = now;
        for (auto it = validations.begin(); it != validations.end();) {
            if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto result = it->get();
                saveValid = saveValid && result["exact_bytes_and_order"].toBool();
                exports.append(result);
                it = validations.erase(it);
            } else
                ++it;
        }
        const auto c = window.captureCounters();
        if (languageCycle && now >= nextLanguage && now < seconds * 1000) {
            const std::array<QString, 3> languages = {"zh_CN", "zh_TW", "en"};
            i18n::language().set(
                languages[static_cast<std::size_t>(languageChanges) % languages.size()]);
            ++languageChanges;
            nextLanguage += 10000;
        }
        if (!panelBound && c.enqueued > 0 && window.findChild<TcpPanel *>()) {
            window.findChild<QPushButton *>("tcpAnalysisDockRebind")->click();
            panelBound = true;
            if (applicationViewLoad) {
                window.findChild<QTabWidget *>("tcpAnalysisTabs")->setCurrentIndex(1);
                auto *pane = window.findChild<StreamPane *>();
                pane->findChild<QTabWidget *>("streamTabs")->setCurrentIndex(2);
                visibleApplication = pane->findChild<ApplicationView *>();
            }
        }
        if (visibleApplication && visibleApplication->isVisible()) {
            auto *list = visibleApplication->findChild<QTreeWidget *>("applicationMessages");
            if (list->topLevelItemCount()) {
                const auto token = list->topLevelItem(0)->data(0,Qt::UserRole+7).toString() + ':' +
                    list->topLevelItem(list->topLevelItemCount()-1)->data(0,Qt::UserRole+7).toString();
                if (token != observedApplicationRows) { ++applicationViewUpdates; observedApplicationRows = token; }
            }
            if (chooseApplicationField && !visibleApplication->updating()) {
                auto *fields = visibleApplication->findChild<QTreeWidget *>("applicationFields");
                if (fields->topLevelItemCount()) fields->setCurrentItem(fields->topLevelItem(0));
                auto *next = visibleApplication->findChild<QPushButton *>("applicationNextPage");
                if (next->isEnabled()) { next->click(); ++applicationPageClicks; }
                chooseApplicationField = false;
            }
        }
        auto *find = window.findChild<FindBar *>("mainFindBar");
        if (findPending && !find->searching()) {
            auto *next = find->findChild<QPushButton *>("findPrevious");
            if (next->isEnabled()) { next->click(); window.findChild<QAction *>("readingBack")->trigger(); ++findInteractions; }
            const auto restored = window.packetModel()->packetAt(window.findChild<QTableView *>("packetTable")->currentIndex().row());
            if (next->isEnabled() && (!restored || restored->id != beforeFindPacket)) --findInteractions;
            find->findChild<QPushButton *>("findClose")->click(); findPending = false;
        }
        if (args.contains("--workspace-interactions") && now >= nextWorkspaceInteraction &&
            window.packetModel()->rowCount() > 0 && panelBound) {
            auto *table = window.findChild<QTableView *>("packetTable");
            table->setCurrentIndex(window.packetModel()->index(window.packetModel()->rowCount() - 1, 2));
            emit table->customContextMenuRequested(QPoint(-1, -1));
            if (auto *menu = window.findChild<QMenu *>("packetContextMenu")) {
                menu->findChild<QAction *>("copyPacketCell")->trigger();
                menu->close();
            }
            auto *dock = window.findChild<AnalysisDock *>("tcpAnalysisDock");
            const auto floating = dock->isFloating();
            dock->setFloating(!floating);
            dock->setFloating(floating);
            ++workspaceInteractions;
            if (args.contains("--find-interactions")) {
                table->setCurrentIndex(window.packetModel()->index(window.packetModel()->rowCount() / 2, 2));
                beforeFindPacket = window.packetModel()->packetAt(table->currentIndex().row())->id;
                find->show(); find->findChild<QComboBox *>("findScope")->setCurrentIndex(0);
                find->findChild<QLineEdit *>("findInput")->setText("TCP");
                find->findChild<QPushButton *>("findRefresh")->click(); findPending = true;
            }
            if (visibleApplication) {
                auto *messages = visibleApplication->findChild<QTreeWidget *>("applicationMessages");
                for (int row=messages->topLevelItemCount()-1;row>=0;--row)
                    if (messages->topLevelItem(row)->text(1)=="A -> B" && messages->topLevelItem(row)->data(0,Qt::UserRole+8).toULongLong()>4096) {
                        messages->setCurrentItem(messages->topLevelItem(row)); chooseApplicationField=true; break;
                    }
            }
            nextWorkspaceInteraction = now + 10000;
        }
        if (streamLoad && now >= nextStream && now < seconds * 1000 && c.enqueued > 0 &&
            !window.tcpConversations().items().empty()) {
            auto *dialog = window.findChild<TcpPanel *>();
            dialog->selectConversation(window.tcpConversations().items().back().id);
            dialog->findChild<QPushButton *>("tcpStreamButton")->click();
            ++streamRequests;
            nextStream = now + 2000;
        }
        if (now >= nextProgress) {
            std::cout << "elapsed_s=" << now / 1000 << " received=" << c.received
                      << " queue_dropped=" << c.queueDropped
                      << " heartbeat_max_ms=" << delays.maximum() << std::endl;
            nextProgress += 60000;
        }
        if (now - lastMemory >= (seconds >= 7200 ? 5000 : 1000)) {
            lastMemory = now;
            memorySamples.append(
                QJsonObject{{"elapsed_ms", double(now)}, {"private_bytes", double(resident())}});
        }
        if (!selected && c.enqueued >= 2000) {
            window.selectPacket(0);
            selected = true;
        }
        if (!theme && c.enqueued >= 5000) {
            QElapsedTimer themeTimer;
            themeTimer.start();
            window.setDarkTheme(false);
            themeUs = themeTimer.nsecsElapsed() / 1000;
            theme = true;
        }
        if (!filtered && now >= seconds * 200) {
            applyProtocol("ICMP");
            intentionalReset = true;
            window.findChild<QComboBox *>("icmpTypeFilter")->setCurrentIndex(3);
            intentionalReset = false;
            filtered = true;
        }
        if (!cleared && now >= seconds * 450) {
            applyProtocol("全部协议");
            cleared = true;
        }
        const bool saveDue = (saveRequests == 0 && now >= std::max(11000, seconds * 300)) ||
                             (saveRequests == 1 && now >= std::max(13000, seconds * 650));
        if (saveDue && !window.saving()) {
            if (window.saveFile(temporary.filePath(QString("capture-%1.pcap").arg(saveRequests))))
                ++saveRequests;
            else
                saveValid = false;
        }
        if (!stopping && now >= seconds * 1000 && c.enqueued >= target) {
            stopping = true;
            stopClock.start();
            window.stopCapture();
        }
        if (stopping && !window.busy() && captureStopMs < 0)
            captureStopMs = stopClock.elapsed();
        if (stopping && !window.recordingBusy() && recordingStopMs < 0)
            recordingStopMs = stopClock.elapsed();
        if (stopping && !window.busy() && !window.applicationBusy() && !window.saving() &&
            !window.recordingBusy() && validations.empty() &&
            (!streamPane || !streamPane->busy())) {
            poll.stop();
            const auto stopMs = captureStopMs;
            const auto final = window.captureCounters();
            const auto recording = window.recordingStats();
            const auto analysis = window.applicationStats();
            double warm = 0, tail = 0;
            int wn = 0, tn = 0;
            std::uint64_t peak = 0;
            const auto warmBegin = std::min(60000, seconds * 250),
                       warmEnd = std::min(120000, seconds * 500);
            for (const auto &value : memorySamples) {
                const auto sample = value.toObject();
                const auto t = sample["elapsed_ms"].toDouble(),
                           bytes = sample["private_bytes"].toDouble();
                peak = std::max(peak, static_cast<std::uint64_t>(bytes));
                if (t >= warmBegin && t < warmEnd) {
                    warm += bytes;
                    ++wn;
                }
                if (t >= seconds * 1000 - std::min(60000, seconds * 200)) {
                    tail += bytes;
                    ++tn;
                }
            }
            const double growth = wn && tn ? tail / tn - warm / wn : 0;
            std::vector<qint64> warmMemory, tailMemory;
            for (const auto &sample : memorySamples) {
                const auto v = sample.toObject();
                const auto t = v["elapsed_ms"].toDouble();
                const auto bytes = static_cast<qint64>(v["private_bytes"].toDouble());
                if (t >= 900000 && t < 1500000)
                    warmMemory.push_back(bytes);
                if (t >= seconds * 1000 - 600000)
                    tailMemory.push_back(bytes);
            }
            const auto medianGrowth =
                seconds >= 7200 ? percentile(tailMemory, 50) - percentile(warmMemory, 50) : 0;
            const auto maximum = delays.maximum();
            const auto p99 = delays.percentile(99), appendP99 = appendTimes.percentile(99),
                       filterMax = filterTimes.maximum();
            const bool counts =
                final.received == target &&
                window.sessionStats().received + final.queueDropped == final.received &&
                final.queuedPackets == 0;
            bool recordingExact = true;
            std::uint64_t recordedRecords = 0, recordedBytes = 0;
            std::int64_t recordedFirst = -1, recordedLast = -1;
            if (recordingLoad) {
                try {
                    QDir directory(recording.directory);
                    const auto files = directory.entryList({"*.pcapng"}, QDir::Files, QDir::Name);
                    recordingExact =
                        !files.empty() && directory.entryList({"*.part"}, QDir::Files).empty();
                    for (const auto &name : files) {
                        recordedBytes +=
                            static_cast<std::uint64_t>(QFileInfo(directory.filePath(name)).size());
                        CaptureReader reader(
                            std::filesystem::path(directory.filePath(name).toStdWString()));
                        while (auto raw = reader.next()) {
                            const auto sequence = (raw->timestampNs - timestampBase) / 1000000;
                            recordingExact =
                                recordingExact && sequence >= 0 &&
                                static_cast<std::uint64_t>(sequence) < target &&
                                (recordedLast < 0 || sequence == recordedLast + 1) &&
                                raw->timestampNs == timestampBase + sequence * 1000000 &&
                                raw->bytes == rawAt(static_cast<std::uint64_t>(sequence)).bytes;
                            if (recordedFirst < 0)
                                recordedFirst = sequence;
                            recordedLast = sequence;
                            ++recordedRecords;
                        }
                    }
                    recordingExact = recordingExact && recordedRecords > 0 &&
                                     recordedLast == static_cast<std::int64_t>(target) - 1 &&
                                     recordedBytes <= 64 * 1024 * 1024;
                } catch (const std::exception &) {
                    recordingExact = false;
                }
            }
            std::size_t expectedRows = expectedRetained;
            if (expression) {
                expectedRows = 0;
                for (auto sequence = target - expectedRetained; sequence < target; ++sequence) {
                    auto packet = decodeSummary(rawAt(sequence));
                    packet.id = sequence + 1;
                    if (expression->evaluate(packet, window.applicationIndex().facts(packet.id)) ==
                        FilterTruth::True)
                        ++expectedRows;
                }
            }
            const bool recordingValid =
                !recordingLoad ||
                (!recording.failed && recording.unwritten == 0 &&
                 recording.written == final.received && recording.queued == 0 && recordingExact);
            const bool passed =
                counts && recordingValid && final.queueDropped == 0 && p99 <= 10 &&
                maximum <= 250 && appendP99 <= 8000 && filterMax <= 100000 && stopMs <= 1000 &&
                peak <= 256 * 1024 * 1024 &&
                (seconds >= 7200 ? (!warmMemory.empty() && !tailMemory.empty() &&
                                    medianGrowth <= 8 * 1024 * 1024)
                                 : growth <= 16 * 1024 * 1024) &&
                window.packetModel()->rowCount() == static_cast<int>(expectedRows) &&
                (!expression || !longHttp || expectedRows > 0) && analysis.rejectedPackets == 0 &&
                analysis.stateBytes <= applicationStateBudget &&
                analysis.retainedBytes <= applicationInputBudget &&
                (!longHttp ||
                 (analysis.deliveredBytes == expectedDelivered && analysis.stateEvictions == 0)) &&
                analysis.queuedBytes == 0 && analysis.pendingUpdates == 0 &&
                analysis.peakStagedBytes <= applicationStagingBudget &&
                (pps > 1000 || analysis.stagingLimitedRecords == 0) &&
                window.applicationIndex().estimatedBytes() <= applicationIndexBudget &&
                window.retainedRawBytes() == expectedRaw &&
                window.retainedEstimatedBytes() <= 64 * 1024 * 1024 && resets == 0 &&
                saveRequests == 2 && exports.size() == 2 && saveValid && streamValid &&
                (!args.contains("--workspace-interactions") || (panelBound && workspaceInteractions >= 5)) &&
                (!applicationViewLoad || (applicationViewUpdates >= 20 && applicationPageClicks >= 3)) &&
                (!args.contains("--find-interactions") || findInteractions >= 5) &&
                (!streamLoad || streamCompleted == streamRequests) &&
                (!languageCycle || languageChanges >= (seconds - 1) / 10);
            QJsonObject report{
                {"kind", "synthetic_source_capture_decode_queue_store_ui"},
                {"version", ETHERSCOPE_VERSION},
                {"find_and_back_interactions", findInteractions},
                {"long_http_connection", longHttp},
                {"application_expression",
                 expression ? QString::fromStdString(expression->source()) : QString{}},
                {"expected_displayed_rows", double(expectedRows)},
                {"expected_delivered_bytes", double(expectedDelivered)},
                {"tcp_fixture", args.contains("--tcp")},
                {"tcp_panel", args.contains("--tcp-panel")},
                {"stream_load", streamLoad},
                {"analysis_panel_bound", panelBound},
                {"workspace_interactions", workspaceInteractions},
                {"large_request_period", double(largePeriod)},
                {"large_request_bytes", double(applicationViewLoad ? largeRequest.size() : 0)},
                {"application_view_updates", applicationViewUpdates},
                {"application_page_clicks", applicationPageClicks},
                {"stream_requests", streamRequests},
                {"stream_completed", streamCompleted},
                {"language_cycle", languageCycle},
                {"language_switches", languageChanges},
                {"tcp_connections", double(window.tcpConversations().items().size())},
                {"tcp_estimated_bytes", double(window.tcpConversations().estimatedBytes())},
                {"tcp_overwritten", double(window.tcpConversations().overwritten())},
                {"tcp_skipped", double(window.tcpConversations().skipped())},
                {"utc", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
                {"requested_seconds", seconds},
                {"target_pps", pps},
                {"elapsed_ms", double(now)},
                {"received", double(final.received)},
                {"parsed", double(window.sessionStats().received)},
                {"achieved_pps", final.received * 1000.0 / now},
                {"queue_dropped", double(final.queueDropped)},
                {"queue_peak_packets", double(final.peakQueuedPackets)},
                {"queue_peak_raw_bytes", double(final.peakQueuedBytes)},
                {"retained_rows", window.packetModel()->rowCount()},
                {"expected_retained_rows", double(expectedRetained)},
                {"retained_estimated_bytes", double(window.retainedEstimatedBytes())},
                {"retained_raw_bytes", double(window.retainedRawBytes())},
                {"heartbeat_p99_delay_ms", double(p99)},
                {"heartbeat_max_delay_ms", double(maximum)},
                {"theme_change_us", double(themeUs)},
                {"batch_p99_us", double(appendP99)},
                {"batch_max_us", double(appendTimes.maximum())},
                {"heartbeat_stalls", stalls},
                {"filter_max_us", double(filterMax)},
                {"model_resets_during_feed", resets},
                {"stop_completed_ms", double(stopMs)},
                {"peak_private_bytes", double(peak)},
                {"tail_growth_bytes", growth},
                {"warm_tail_median_growth_bytes", double(medianGrowth)},
                {"recording_exact_bytes_and_order", recordingExact},
                {"recording_retained_records", double(recordedRecords)},
                {"recording_first_sequence", double(recordedFirst)},
                {"recording_last_sequence", double(recordedLast)},
                {"recording_retained_bytes", double(recordedBytes)},
                {"recording_enabled", recordingLoad},
                {"recording_written", double(recording.written)},
                {"recording_unwritten", double(recording.unwritten)},
                {"recording_finalize_ms", double(recordingStopMs)},
                {"recording_valid", recordingValid},
                {"application_index_bytes", double(window.applicationIndex().estimatedBytes())},
                {"analysis_complete",
                 double(window.applicationIndex().diagnostics().count(AnalysisStatus::Complete))},
                {"analysis_pending",
                 double(window.applicationIndex().diagnostics().count(AnalysisStatus::Pending))},
                {"analysis_data_missing",
                 double(window.applicationIndex().diagnostics().count(AnalysisStatus::Incomplete))},
                {"analysis_resource_limited",
                 double(window.applicationIndex().diagnostics().count(AnalysisStatus::Limited))},
                {"analysis_missing_keys", double(window.applicationIndex().diagnostics().count(
                                              AnalysisStatus::MissingKeys))},
                {"analysis_unsupported", double(window.applicationIndex().diagnostics().count(
                                             AnalysisStatus::Unsupported))},
                {"analysis_authentication_failed",
                 double(window.applicationIndex().diagnostics().count(
                     AnalysisStatus::AuthenticationFailed))},
                {"analysis_index_evictions",
                 double(window.applicationIndex().diagnostics().evictedEntries)},
                {"filter_evaluations", double(window.packetModel()->evaluations())},
                {"analysis_submitted_packets", double(analysis.submittedPackets)},
                {"analysis_rejected_packets", double(analysis.rejectedPackets)},
                {"analysis_completed_updates", double(analysis.completedUpdates)},
                {"analysis_delivered_bytes", double(analysis.deliveredBytes)},
                {"analysis_key_replays", double(analysis.keyReplays)},
                {"analysis_state_evictions", double(analysis.stateEvictions)},
                {"analysis_coalesced_updates", double(analysis.coalescedUpdates)},
                {"analysis_staging_limited_records", double(analysis.stagingLimitedRecords)},
                {"analysis_staging_limited_updates", double(analysis.stagingLimitedUpdates)},
                {"analysis_compacted_updates", double(analysis.compactedUpdates)},
                {"analysis_compacted_messages", double(analysis.compactedMessages)},
                {"analysis_pending_limited_packets", double(analysis.pendingLimitedPackets)},
                {"analysis_peak_result_bytes", double(analysis.peakResultBytes)},
                {"analysis_peak_fact_bytes", double(analysis.peakFactBytes)},
                {"analysis_staging_peak_bytes", double(analysis.peakStagedBytes)},
                {"analysis_state_bytes", double(analysis.stateBytes)},
                {"analysis_retained_bytes", double(analysis.retainedBytes)},
                {"analysis_unresolved_pending",
                 double(window.applicationIndex().diagnostics().count(AnalysisStatus::Pending))},
                {"analysis_unresolved_incomplete",
                 double(window.applicationIndex().diagnostics().incomplete())},
                {"cpu_single_core_average_percent", (cpuSeconds() - cpuStart) * 100000.0 / now},
                {"exports", exports},
                {"memory_samples", memorySamples},
                {"counts_reconciled", counts},
                {"passed", passed}};
            QFile file(output);
            if (!file.open(QIODevice::WriteOnly)) {
                app.exit(3);
                return;
            }
            file.write(QJsonDocument(report).toJson());
            std::cout << "packets=" << final.received << " p99_ms=" << p99 << " stop_ms=" << stopMs
                      << " passed=" << passed << "\n";
            app.exit(passed ? 0 : 1);
        }
        if (now > seconds * 1000 + 15000)
            app.exit(4);
    });
    QObject::connect(&window, &MainWindow::interfacesFinished, &app, [&] {
        intentionalReset = true;
        window.findChild<QPushButton *>("startButton")->click();
        intentionalReset = false;
    });
    poll.start(20);
    return app.exec();
}
