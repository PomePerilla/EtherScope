#include "ui/main_window.h"
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableView>
#include <QTabBar>
#include <QTreeWidget>
#include "core/pcap_file.h"
#include "ui/helpers.h"
#include "ui/filter_chip.h"
#include "ui/tcp_dialog.h"
#include "ui/style.h"
#include "ui/language.h"
#include <QAction>
#include <QDialog>
#include <QDialogButtonBox>
#include <QApplication>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QCloseEvent>
#include <QDir>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QWheelEvent>
#include <QScreen>
#include <QScrollBar>
#include <QScopedValueRollback>
#include <QSettings>
#include <QResource>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStandardPaths>
#include <QStatusBar>
#include <QTextBlock>
#include <QVBoxLayout>
#include <QStandardItemModel>
#include <QTreeView>
#include <algorithm>
#include <filesystem>
#include <functional>
#include <utility>

static void initDesktopResources() {
    Q_INIT_RESOURCE(desktop_icons);
    Q_INIT_RESOURCE(brand_icons);
}
namespace etherscope {
namespace {
CaptureHooks observeRaw(CaptureHooks hooks, std::function<void(const RawPacket &)> observe) {
    auto previous = std::move(hooks.rawObserver);
    hooks.rawObserver = [observe = std::move(observe),
                         previous = std::move(previous)](const RawPacket &raw) {
        if (previous)
            previous(raw);
        observe(raw);
    };
    return hooks;
}
} // namespace
MainWindow::MainWindow(QWidget *parent, MainWindowOptions options)
    : QMainWindow(parent),
      preparation_(this, options.capture.interfaces, std::move(options.prepareFile)),
      engine_(this, observeRaw(std::move(options.capture),
                               [this](const RawPacket &raw) {
                                   if (recordingSession_)
                                       recording_.submit(raw);
                               })),
      exporter_(this, std::move(options.exportWriter)),
      details_(this, std::move(options.detailDecoder)),
      recording_(this, std::move(options.recording)),
      snapshotObserver_(std::move(options.snapshotObserver)) {
    initDesktopResources();
    streamDecoder_ = std::move(options.streamDecoder);
    const auto config =
        options.settingsFile.isEmpty()
            ? QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/settings.ini"
            : options.settingsFile;
    QDir().mkpath(QFileInfo(config).absolutePath());
    settings_ = std::make_unique<QSettings>(config, QSettings::IniFormat);
    auto selectedLanguage =
        options.language == "auto"
            ? settings_->value("ui/language", i18n::systemLanguage()).toString()
            : (options.language.isEmpty() ? settings_->value("ui/language", "zh_CN").toString()
                                          : options.language);
    if (!i18n::language().set(selectedLanguage))
        i18n::language().set("en");
    buildUi();
    initializeAnalysis(options);
    connect(&i18n::language(), &i18n::Language::changed, this, &MainWindow::retranslate);
    connect(theme_, &QAction::toggled, this, &MainWindow::setDarkTheme);
    connect(refresh_, &QAction::triggered, this, &MainWindow::refreshInterfaces);
    connect(devices_, &QComboBox::currentIndexChanged, this, [this](int index) {
        if (index >= 0)
            preferredDevice_ = devices_->currentData().toString();
        updateButtons();
    });
    connect(start_, &QPushButton::clicked, this, &MainWindow::startCapture);
    connect(stop_, &QPushButton::clicked, this, &MainWindow::stopCapture);
    connect(open_, &QPushButton::clicked, this, [this] {
        auto path = QFileDialog::getOpenFileName(
            this, i18n::text("打开文件"), usableDirectory(openDirectory_),
            i18n::text("Capture files (*.pcapng *.pcap *.cap)"), nullptr,
            QFileDialog::DontUseNativeDialog);
        if (!path.isEmpty())
            openFile(path);
    });
    connect(save_, &QPushButton::clicked, this, [this] {
        QString format;
        auto path = QFileDialog::getSaveFileName(
            this, i18n::text("保存文件"),
            QDir(usableDirectory(saveDirectory_)).filePath("capture.pcapng"),
            "PCAPNG (*.pcapng);;PCAP (*.pcap)", &format, QFileDialog::DontUseNativeDialog);
        if (!path.isEmpty())
            saveFile(path,
                     format.startsWith("PCAPNG") ? CaptureFormat::Pcapng : CaptureFormat::Pcap);
    });
    connect(apply_, &QPushButton::clicked, this, &MainWindow::applyFilter);
    connect(mac_, &QLineEdit::returnPressed, this, &MainWindow::applyFilter);
    connect(ip_, &QLineEdit::returnPressed, this, &MainWindow::applyFilter);
    connect(protocol_, &QComboBox::currentIndexChanged, this, [this](int index) {
        auto filter = model_->filter();
        filter.protocol = index == 0 ? "" : protocol_->itemText(index).toStdString();
        filter.icmpType.reset();
        filter.tcpConversationId.reset();
        commitFilter(std::move(filter));
    });
    connect(icmpType_, &QComboBox::currentIndexChanged, this, [this] {
        auto filter = model_->filter();
        if (filter.protocol != "ICMP")
            return;
        const auto type = icmpType_->currentData().toInt();
        filter.icmpType =
            type < 0 ? std::nullopt : std::optional<std::uint8_t>(static_cast<std::uint8_t>(type));
        commitFilter(std::move(filter));
    });
    connect(clear_, &QPushButton::clicked, this, [this] {
        mac_->clear();
        ip_->clear();
        macDirection_->setCurrentIndex(0);
        ipDirection_->setCurrentIndex(0);
        {
            QSignalBlocker block(protocol_);
            protocol_->setCurrentIndex(0);
        }
        commitFilter({});
        macError_->hide();
        ipError_->hide();
        style::setFlag(mac_, "invalid", false);
        style::setFlag(ip_, "invalid", false);
    });
    connect(macChip_, &QPushButton::clicked, this, [this] {
        auto filter = model_->filter();
        filter.mac.reset();
        filter.macDirection = Direction::Either;
        mac_->clear();
        macDirection_->setCurrentIndex(0);
        macError_->hide();
        style::setFlag(mac_, "invalid", false);
        commitFilter(std::move(filter));
    });
    connect(ipChip_, &QPushButton::clicked, this, [this] {
        auto filter = model_->filter();
        filter.ip.reset();
        filter.ipv6.reset();
        filter.ipDirection = Direction::Either;
        ip_->clear();
        ipDirection_->setCurrentIndex(0);
        ipError_->hide();
        style::setFlag(ip_, "invalid", false);
        commitFilter(std::move(filter));
    });
    connect(protocolChip_, &QPushButton::clicked, this, [this] { protocol_->setCurrentIndex(0); });
    connect(icmpChip_, &QPushButton::clicked, this, [this] { icmpType_->setCurrentIndex(0); });
    connect(conversationChip_, &QPushButton::clicked, this, [this] {
        auto filter = model_->filter();
        filter.tcpConversationId.reset();
        commitFilter(std::move(filter));
    });
    connect(modes_, &QTabBar::currentChanged, this, &MainWindow::switchMode);
    connect(table_->selectionModel(), &QItemSelectionModel::currentRowChanged, this, [this] {
        if (!updatingSelection_)
            showDetails();
    });
    connect(table_, &QTableView::clicked, this, [this](const QModelIndex &index) {
        if (view_ == 0 && index.row() != model_->rowCount() - 1)
            follow_->setChecked(false);
    });
    connect(follow_, &QCheckBox::toggled, this, [this](bool checked) {
        if (checked && view_ == 0)
            table_->scrollToBottom();
    });
    table_->installEventFilter(this);
    table_->viewport()->installEventFilter(this);
    table_->verticalScrollBar()->installEventFilter(this);
    connect(table_->verticalScrollBar(), &QScrollBar::sliderMoved, this, [this](int value) {
        if (view_ == 0 && value < table_->verticalScrollBar()->maximum())
            follow_->setChecked(false);
    });
    connect(table_->verticalScrollBar(), &QScrollBar::actionTriggered, this, [this] {
        if (view_ == 0 &&
            table_->verticalScrollBar()->sliderPosition() < table_->verticalScrollBar()->maximum())
            follow_->setChecked(false);
    });
    connect(fields_, &QTreeWidget::currentItemChanged, this,
            [this](QTreeWidgetItem *item) { highlightBytes(item); });
    connect(fields_, &QTreeWidget::itemCollapsed, this, [this](QTreeWidgetItem *item) {
        collapsedFields_.insert(item->data(0, Qt::UserRole + 2).toString());
    });
    connect(fields_, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem *item) {
        collapsedFields_.remove(item->data(0, Qt::UserRole + 2).toString());
    });
    connect(previousBytes_, &QPushButton::clicked, this, [this] {
        renderHexPage(hexStart_ >= hexPageSize_ ? hexStart_ - hexPageSize_ : 0);
        highlightBytes(fields_->currentItem(), false);
    });
    connect(nextBytes_, &QPushButton::clicked, this, [this] {
        renderHexPage(hexStart_ + hexPageSize_);
        highlightBytes(fields_->currentItem(), false);
    });
    connect(
        &preparation_, &PreparationService::interfacesReady, this,
        [this](quint64 request, CaptureInterfaces interfaces, const QString &error,
               bool cancelled) {
            if (request != preparation_.interfaceGeneration())
                return;
            queryingInterfaces_ = false;
            if (!cancelled && !closing_) {
                const auto previous = devices_->currentData().toString().isEmpty()
                                          ? preferredDevice_
                                          : devices_->currentData().toString();
                QSignalBlocker block(devices_);
                auto *model = qobject_cast<QStandardItemModel *>(devices_->model());
                model->removeRows(0, model->rowCount());
                for (const auto &device : interfaces) {
                    auto *name = new QStandardItem(device.description);
                    name->setData(device.name, Qt::UserRole);
                    name->setToolTip(device.description);
                    auto *addresses = new QStandardItem(device.addresses);
                    addresses->setToolTip(device.addresses);
                    model->appendRow({name, addresses});
                }
                if (!previous.isEmpty())
                    devices_->setCurrentIndex(devices_->findData(previous));
                if (devices_->currentIndex() >= 0)
                    preferredDevice_ = devices_->currentData().toString();
                auto *view = qobject_cast<QTreeView *>(devices_->view());
                view->resizeColumnToContents(0);
                view->resizeColumnToContents(1);
                sourceStatus_[0] = !error.isEmpty() ? error.toStdString()
                                                    : (interfaces.empty() ? "无可用接口" : "就绪");
            }
            updateStatus();
            updateButtons();
            emit interfacesFinished(request);
            tryClose();
        },
        Qt::QueuedConnection);
    connect(
        &preparation_, &PreparationService::fileReady, this,
        [this](quint64 request, const QString &path, PreparedFile reader, const QString &error,
               bool cancelled) {
            if (request != fileRequest_ || !openingFile_)
                return;
            preparingFile_ = false;
            if (cancelled || closing_ || fileCancelRequested_) {
                completeFileOpen(FileOpenResult::Cancelled);
                tryClose();
                return;
            }
            if (!reader) {
                reportError(error);
                completeFileOpen(FileOpenResult::Failure, error);
                return;
            }
            if (!scheduleAction(
                    [this, path, reader = std::move(reader)] { beginFile(path, reader); })) {
                completeFileOpen(FileOpenResult::Cancelled);
            }
        },
        Qt::QueuedConnection);
    connect(
        &details_, &DetailService::changed, this,
        [this] {
            auto result = details_.takeResult();
            if (result && !closing_ && result->request == detailRequest_ &&
                result->packet == selected_) {
                if (!result->error.isEmpty()) {
                    detailsPending_ = false;
                    i18n::setLabel(detailIssues_, result->error);
                    emit detailsFinished(detailRequest_);
                } else {
                    selectedDetails_ = std::move(result->details);
                    appendDnsFields();
                    for (auto field = selectedDetails_->fields.rbegin();
                         field != selectedDetails_->fields.rend(); ++field)
                        fieldItems_.push_back({nullptr, &*field});
                    detailTimer_.start(0);
                    fillDetails();
                }
                updateStatus();
            }
            tryClose();
        },
        Qt::QueuedConnection);
    connect(&detailTimer_, &QTimer::timeout, this, &MainWindow::fillDetails);
    connect(&engine_, &CaptureEngine::opened, this, [this](quint64 epoch, const QString &text) {
        if (epoch != engine_.generation() || active_ < 0)
            return;
        if (active_ == 0 && liveStarting_) {
            if (state_ == CaptureState::Stopping)
                return;
            liveStarting_ = false;
            model_->clear();
            resetApplications(0);
            updateFilterStatus();
            selected_.reset();
            showDetails();
            counters_[0] = {};
            resetRates();
            refreshTcpConversations();
            successfulBpf_ = startingOptions_.bpf;
            sessionBpf_ = successfulBpf_;
            bpfError_.clear();
        }
        if (active_ == 1)
            openDirectory_ = QFileInfo(filePath_).absolutePath();
        if (state_ != CaptureState::Stopping) {
            state_ = CaptureState::Running;
            sourceStatus_[active_] = text.toStdString();
        }
        updateStatus();
        updateButtons();
    });
    connect(&engine_, &CaptureEngine::failed, this, [this](quint64 epoch, const QString &text) {
        if (epoch != engine_.generation() || active_ < 0)
            return;
        if (text.startsWith("捕获过滤"))
            bpfError_ = text;
        failed_[active_] = true;
        sourceStatus_[active_] = text.toStdString();
        updateStatus();
        updateButtons();
    });
    connect(&engine_, &CaptureEngine::finished, this, [this](quint64 epoch) {
        if (epoch != engine_.generation() || active_ < 0)
            return;
        producerFinished_ = true;
        flush();
    });
    connect(&exporter_, &ExportEngine::progress, this,
            [this](quint64 job, quint64 recordsWritten, quint64 totalRecords) {
                if (saving_ && job == exporter_.generation()) {
                    const auto boundedRecords = std::min(recordsWritten, totalRecords);
                    const auto percent = totalRecords
                                             ? (boundedRecords == totalRecords
                                                    ? 100
                                                    : static_cast<int>(
                                                          100.0L * boundedRecords / totalRecords))
                                             : 0;
                    i18n::setLabel(exportLabel_, "正在保存 %1%",
                                   {QString::number(std::clamp(percent, 0, 100))});
                }
            });
    connect(&exporter_, &ExportEngine::finished, this,
            [this](quint64 job, bool success, const QString &path, quint64 count,
                   const QString &error) {
                if (job != exporter_.generation() || !saving_)
                    return;
                saving_ = false;
                i18n::setLabel(exportLabel_, {});
                if (success) {
                    saveDirectory_ = QFileInfo(path).absolutePath();
                    i18n::setLabel(exportLabel_, "已保存 %1 包", {QString::number(count)});
                    QTimer::singleShot(12000, this, [this, job] {
                        if (!saving_ && exporter_.generation() == job)
                            i18n::setLabel(exportLabel_, {});
                    });
                } else {
                    const bool restore = closing_;
                    closing_ = false;
                    if (restore) {
                        selected_.reset();
                        showDetails();
                    }
                    reportError(error);
                }
                updateStatus();
                updateButtons();
                emit saveFinished(success, path, count, error);
                tryClose();
            });
    connect(&batchTimer_, &QTimer::timeout, this, &MainWindow::flush);
    batchTimer_.start(100);
    connect(&rateTimer_, &QTimer::timeout, this, [this] {
        const double seconds = std::max(0.001, rateClock_.restart() / 1000.0);
        const auto c = counters_[view_];
        const auto timed = c.received - c.untimedPackets, timedBytes = c.bytes - c.untimedBytes;
        const auto count = timed >= lastCount_ ? timed - lastCount_ : 0,
                   bytes = timedBytes >= lastBytes_ ? timedBytes - lastBytes_ : 0;
        chart_->addSample(count / seconds, bytes / seconds);
        chart_->setProtocols(currentStore().stats().protocols);
        lastCount_ = timed;
        lastBytes_ = timedBytes;
        refreshTcpConversations();
    });
    rateClock_.start();
    rateTimer_.start(1000);
    setDarkTheme(true);
    restoreSettings();
    retranslate();
    refreshInterfaces();
    updateStatus();
    updateButtons();
}
MainWindow::~MainWindow() {
    details_.requestStop();
    engine_.stop();
    for (auto &service : applications_)
        service->requestStop();
    recording_.finish();
    saveSettings();
}
void MainWindow::refreshInterfaces() {
    if (closing_ || preparation_.discovering() || state_ != CaptureState::Idle || openingFile_)
        return;
    actionError_.clear();
    sourceStatus_[0] = "查询网卡";
    queryingInterfaces_ = true;
    preparation_.requestInterfaces();
    updateStatus();
    updateButtons();
}
void MainWindow::configureCaptureFilter() {
    if (bpfDialog_) {
        bpfDialog_->raise();
        bpfDialog_->activateWindow();
        return;
    }
    auto *dialog = new QDialog(this);
    bpfDialog_ = dialog;
    dialog->setObjectName("captureFilterDialog");
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle("捕获过滤");
    dialog->setMinimumWidth(420);
    auto *layout = new QVBoxLayout(dialog);
    auto *input = new QLineEdit(bpfDraft_, dialog);
    bpfInput_ = input;
    input->setObjectName("bpfInput");
    input->setPlaceholderText("tcp port 443");
    input->setReadOnly(busy());
    layout->addWidget(input);
    auto *error = new QLabel(bpfError_, dialog);
    error->setWordWrap(true);
    error->setProperty("error", true);
    error->setObjectName("bpfError");
    layout->addWidget(error);
    auto *buttons = new QDialogButtonBox(dialog);
    auto *apply = buttons->addButton("应用", QDialogButtonBox::AcceptRole);
    bpfApply_ = apply;
    apply->setObjectName("applyBpfButton");
    apply->setEnabled(!busy());
    buttons->addButton("关闭", QDialogButtonBox::RejectRole);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, dialog, [this, input, dialog] {
        if (!busy() && !closing_) {
            bpfDraft_ = input->text().trimmed();
            bpfError_.clear();
            dialog->accept();
        }
    });
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    error->setText({});
    i18n::bind(dialog);
    i18n::setLabel(error, bpfError_);
    dialog->show();
}
void MainWindow::startCapture() {
    if (discovering() || openingFile_ || recordingBusy() ||
        devices_->currentData().toString().isEmpty())
        return;
    const auto device = devices_->currentData().toString();
    const LiveCaptureOptions options{bpfDraft_};
    scheduleAction([this, device, options] { beginLive(device, options); });
}
bool MainWindow::scheduleAction(std::function<void()> action) {
    if (closing_ || state_ == CaptureState::Stopping)
        return false;
    if (state_ != CaptureState::Idle) {
        pendingAction_ = std::move(action);
        requestCaptureStop();
    } else
        action();
    return true;
}
void MainWindow::beginLive(const QString &device, LiveCaptureOptions options) {
    recordingSession_ = recordingOptions_.enabled;
    if (recordingSession_ && !recording_.start(recordingOptions_)) {
        recordingSession_ = false;
        reportError("Recording could not start");
        return;
    }
    // Completion remains pending until the GUI has handled success or failure.
    recordingPending_ = recordingSession_;
    actionError_.clear();
    showMode(0);
    liveStarting_ = true;
    startingOptions_ = std::move(options);
    failed_[0] = false;
    sourceStatus_[0] = "连接中";
    preferredDevice_ = device;
    state_ = CaptureState::Starting;
    active_ = 0;
    producerFinished_ = false;
    resetRates();
    engine_.startLive(device, startingOptions_);
    updateStatus();
    updateButtons();
}
void MainWindow::stopCapture() {
    if (openingFile_) {
        if (preparingFile_) {
            fileCancelRequested_ = true;
            preparation_.cancelFile();
        } else if (activeFileRequest_ != fileRequest_ || active_ != 1) {
            pendingAction_ = {};
            completeFileOpen(FileOpenResult::Cancelled);
        }
    }
    requestCaptureStop();
}
void MainWindow::requestCaptureStop() {
    if (state_ == CaptureState::Idle || state_ == CaptureState::Stopping)
        return;
    state_ = CaptureState::Stopping;
    if (active_ >= 0 && !failed_[active_])
        sourceStatus_[active_] = "停止中";
    engine_.requestStop();
    updateStatus();
    updateButtons();
}
void MainWindow::flush() {
    if (active_ < 0)
        return;
    if (liveStarting_) {
        if (producerFinished_) {
            engine_.takeBatch();
            finishCapture();
        }
        return;
    }
    QElapsedTimer elapsed;
    elapsed.start();
    std::size_t limit = 512;
    if (snapshotPending_ && snapshotSession_ == active_) {
        const auto &store = active_ == 0 ? live_ : file_;
        limit = static_cast<std::size_t>(std::min<std::uint64_t>(
            limit, snapshotBoundary_ - std::min(snapshotBoundary_, store.stats().received)));
    }
    auto batch = engine_.takeBatch(limit);
    if (!batch.empty()) {
        if (active_ == view_) {
            QScopedValueRollback<bool> changing(updatingSelection_, true);
            model_->append(std::move(batch));
            if (!table_->currentIndex().isValid() && model_->rowCount() > 0)
                table_->setCurrentIndex(model_->index(0, 0));
            showDetails();
            if (follow_->isChecked() && view_ == 0)
                table_->scrollToBottom();
        } else {
            auto &store = active_ == 0 ? live_ : file_;
            for (auto &packet : batch)
                store.append(std::move(packet));
        }
        submitApplications(active_);
    }
    counters_[active_] = engine_.counters();
    if (snapshotPending_) {
        const auto &store = snapshotSession_ == 0 ? live_ : file_;
        if (store.stats().received >= snapshotBoundary_)
            startSnapshotExport();
    }
    updateStatus();
    if (!saving_ && !closing_ && !currentStore().packets().empty() && !save_->isEnabled())
        save_->setEnabled(true);
    emit batchProcessed(elapsed.nsecsElapsed() / 1000);
    if (producerFinished_ && counters_[active_].queuedPackets == 0) {
        finishCapture();
    } else if (counters_[active_].queuedPackets > 0 && !drainScheduled_) {
        drainScheduled_ = true;
        QTimer::singleShot(0, this, [this] {
            drainScheduled_ = false;
            flush();
        });
    }
}
void MainWindow::finishCapture() {
    if (active_ == 0 && recordingSession_)
        recording_.finish();
    const bool stopped = state_ == CaptureState::Stopping;
    const int finishedSession = active_;
    if (!failed_[active_])
        sourceStatus_[active_] =
            active_ == 1 ? (stopped ? "读取已停止" : "读取完成") : (stopped ? "已停止" : "已结束");
    active_ = -1;
    liveStarting_ = false;
    state_ = CaptureState::Idle;
    producerFinished_ = false;
    if (openingFile_ && finishedSession == 1 && activeFileRequest_ == fileRequest_)
        completeFileOpen(failed_[1]
                             ? FileOpenResult::Failure
                             : (stopped ? FileOpenResult::Cancelled : FileOpenResult::Success),
                         failed_[1] ? q(sourceStatus_[1]) : QString{});
    auto action = std::exchange(pendingAction_, {});
    if (action && !closing_)
        action();
    updateStatus();
    updateButtons();
    refreshTcpConversations();
    tryClose();
}
void MainWindow::switchMode(int index) {
    if (index == view_)
        return;
    if (openingFile_) {
        QSignalBlocker block(modes_);
        modes_->setCurrentIndex(view_);
        return;
    }
    {
        QSignalBlocker block(modes_);
        modes_->setCurrentIndex(view_);
    }
    scheduleAction([this, index] { showMode(index); });
}
void MainWindow::showMode(int index) {
    {
        QSignalBlocker block(modes_);
        modes_->setCurrentIndex(index);
    }
    if (view_ == index)
        return;
    actionError_.clear();
    view_ = index;
    selected_.reset();
    model_->setApplicationIndex(&applicationIndex_[view_]);
    model_->setStore(&currentStore());
    updateFilterStatus();
    showDetails();
    resetRates();
    updateStatus();
    updateButtons();
    refreshTcpConversations();
    if (model_->rowCount() > 0)
        table_->setCurrentIndex(model_->index(0, 0));
}
bool MainWindow::openFile(const QString &path) {
    if (closing_ || openingFile_ || state_ == CaptureState::Stopping || path.isEmpty())
        return false;
    openingFile_ = true;
    preparingFile_ = true;
    fileCancelRequested_ = false;
    openingPath_ = path;
    actionError_.clear();
    if (!preparation_.requestFile(path)) {
        openingFile_ = false;
        preparingFile_ = false;
        return false;
    }
    fileRequest_ = preparation_.fileGeneration();
    updateStatus();
    updateButtons();
    return true;
}
void MainWindow::completeFileOpen(FileOpenResult result, const QString &error) {
    if (!openingFile_)
        return;
    openingFile_ = false;
    preparingFile_ = false;
    emit fileOpenFinished(fileRequest_, result, openingPath_, error);
    updateStatus();
    updateButtons();
}
void MainWindow::beginFile(const QString &path, PreparedFile reader) {
    activeFileRequest_ = fileRequest_;
    actionError_.clear();
    showMode(1);
    model_->clear();
    resetApplications(1);
    updateFilterStatus();
    refreshTcpConversations();
    selected_.reset();
    failed_[1] = false;
    counters_[1] = {};
    sourceStatus_[1] = "读取中";
    fileName_ = QFileInfo(path).fileName();
    filePath_ = path;
    active_ = 1;
    producerFinished_ = false;
    state_ = CaptureState::Starting;
    resetRates();
    engine_.startFile(path, std::move(reader));
    updateStatus();
    updateButtons();
}
bool MainWindow::saveFile(const QString &path, std::optional<CaptureFormat> format) {
    if (saving_ || closing_ || path.isEmpty())
        return false;
    const auto &store = currentStore();
    const auto boundary =
        active_ == view_ && !liveStarting_ ? engine_.counters().enqueued : store.stats().received;
    if (store.packets().empty() && boundary <= store.stats().received) {
        reportError("缓存为空");
        return false;
    }
    saving_ = true;
    snapshotPending_ = true;
    snapshotPath_ = path;
    snapshotSession_ = view_;
    snapshotBoundary_ = boundary;
    snapshotFormat_ = format.value_or(path.endsWith(".pcap", Qt::CaseInsensitive) ||
                                              path.endsWith(".cap", Qt::CaseInsensitive)
                                          ? CaptureFormat::Pcap
                                          : CaptureFormat::Pcapng);
    actionError_.clear();
    i18n::setLabel(exportLabel_, "正在保存 0%");
    updateStatus();
    updateButtons();
    if (store.stats().received >= snapshotBoundary_)
        startSnapshotExport();
    else if (!drainScheduled_) {
        drainScheduled_ = true;
        QTimer::singleShot(0, this, [this] {
            drainScheduled_ = false;
            flush();
        });
    }
    return true;
}
void MainWindow::startSnapshotExport() {
    const auto &store = snapshotSession_ == 0 ? live_ : file_;
    PacketSnapshot snapshot(store.packets().begin(), store.packets().end());
    if (snapshotObserver_)
        snapshotObserver_(snapshot);
    snapshotPending_ = false;
    if (!exporter_.start(snapshotPath_, std::move(snapshot), snapshotFormat_)) {
        saving_ = false;
        closing_ = false;
        i18n::setLabel(exportLabel_, {});
        reportError("保存启动失败");
        updateButtons();
        emit saveFinished(false, snapshotPath_, 0, "保存启动失败");
    }
    updateStatus();
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (!busy() && !preparation_.busy() && !details_.busy() && !saving_ && !recordingBusy() &&
        !applications_[0]->busy() && !applications_[1]->busy() &&
        (!tcpDialog_ || !tcpDialog_->streamBusy())) {
        if (tcpDialog_)
            tcpDialog_->close();
        saveSettings();
        event->accept();
        return;
    }
    event->ignore();
    closing_ = true;
    if (tcpDialog_)
        tcpDialog_->close();
    detailTimer_.stop();
    fieldItems_.clear();
    detailsPending_ = false;
    details_.cancel();
    pendingAction_ = {};
    preparation_.requestStop();
    for (int session = 0; session < 2; ++session) {
        applications_[session]->reset();
        applicationSubmitted_[session] = 0;
    }
    stopCapture();
    if (!busy())
        recording_.finish();
    updateStatus();
    updateButtons();
    tryClose();
}
void MainWindow::tryClose() {
    if (!closing_ || busy() || preparation_.busy() || details_.busy() || saving_ ||
        recordingBusy() || applications_[0]->busy() || applications_[1]->busy() ||
        (tcpDialog_ && tcpDialog_->streamBusy()) || closeScheduled_)
        return;
    closeScheduled_ = true;
    QTimer::singleShot(0, this, [this] {
        closeScheduled_ = false;
        if (closing_ && !busy() && !preparation_.busy() && !details_.busy() && !saving_ &&
            (!tcpDialog_ || !tcpDialog_->streamBusy()))
            close();
    });
}
bool MainWindow::eventFilter(QObject *watched, QEvent *event) {
    if (event->type() == QEvent::Resize) {
        if (table_ && watched == table_->viewport() && emptyState_)
            emptyState_->setGeometry(table_->viewport()->rect());
        if (fields_ && watched == fields_->viewport() && fieldEmpty_)
            fieldEmpty_->setGeometry(fields_->viewport()->rect());
    }
    if (watched == expressionInput_ && event->type() == QEvent::KeyPress &&
        static_cast<QKeyEvent *>(event)->key() == Qt::Key_Escape) {
        expressionAction_->setChecked(false);
        return true;
    }
    if (event->type() == QEvent::KeyPress &&
        static_cast<QKeyEvent *>(event)->key() == Qt::Key_Escape && addressPanel_->isVisible()) {
        auto *widget = qobject_cast<QWidget *>(watched);
        if (widget && addressPanel_->isAncestorOf(widget)) {
            addressToggle_->setChecked(false);
            addressToggle_->setFocus();
            return true;
        }
    }
    const bool tableInput = watched == table_ || watched == table_->viewport() ||
                            watched == table_->verticalScrollBar();
    bool navigation = false, wheel = false;
    if (event->type() == QEvent::KeyPress) {
        const auto key = static_cast<QKeyEvent *>(event)->key();
        navigation = key == Qt::Key_Up || key == Qt::Key_Down || key == Qt::Key_PageUp ||
                     key == Qt::Key_PageDown || key == Qt::Key_Home || key == Qt::Key_End;
    } else if (event->type() == QEvent::Wheel) {
        auto *value = static_cast<QWheelEvent *>(event);
        wheel = value->angleDelta().y() != 0 || value->pixelDelta().y() != 0;
    }
    if (view_ == 0 && tableInput && (wheel || navigation)) {
        QTimer::singleShot(0, this, [this, navigation] {
            if (view_ == 0 &&
                (table_->verticalScrollBar()->value() < table_->verticalScrollBar()->maximum() ||
                 (navigation && table_->currentIndex().isValid() &&
                  table_->currentIndex().row() != model_->rowCount() - 1)))
                follow_->setChecked(false);
        });
    }
    return QMainWindow::eventFilter(watched, event);
}
void MainWindow::selectPacket(int row) {
    if (row >= 0 && row < model_->rowCount())
        table_->setCurrentIndex(model_->index(row, 0));
}
void MainWindow::ingestBenchmark(std::vector<Packet> packets) {
    if (busy() || closing_)
        return;
    if (view_ != 1)
        showMode(1);
    sourceStatus_[1] = "测试中";
    for (const auto &p : packets) {
        ++counters_[1].received;
        counters_[1].bytes += p.raw.originalLength;
        if (!p.raw.timestampValid) {
            ++counters_[1].untimedPackets;
            counters_[1].untimedBytes += p.raw.originalLength;
        }
    }
    model_->append(std::move(packets));
    submitApplications(view_);
    showDetails();
    updateStatus();
    updateButtons();
}
} // namespace etherscope
