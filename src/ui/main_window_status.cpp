#include "ui/main_window.h"
#include "ui/helpers.h"
#include "ui/language.h"
#include "ui/style.h"
#include "ui/filter_chip.h"
#include "ui/icons.h"
#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableView>
#include <QTabBar>
#include <QToolButton>
#include <QTreeWidget>
#include <QPlainTextEdit>
namespace etherscope {
void MainWindow::updateStatus() {
    if (!status_)
        return;
    bpfMarker_->setVisible(view_ == 0 && !sessionBpf_.isEmpty());
    bpfMarker_->setToolTip(sessionBpf_);
    const auto statusText = i18n::errorText(
        closing_ ? QString("退出中")
                 : (!actionError_.isEmpty()
                        ? actionError_
                        : (preparingFile_ ? QString("准备文件") : q(sourceStatus_[view_]))));
    const bool error = failed_[view_] || !actionError_.isEmpty();
    if (statusText != lastStatusText_) {
        lastStatusText_ = statusText;
        status_->setText(statusText);
        status_->setToolTip(statusText);
    }
    if (error != lastStatusError_) {
        lastStatusError_ = error;
        style::setFlag(status_, "error", error);
    }
    style::setFlag(status_, "success", !error && view_ == 0 && state_ == CaptureState::Running);
    const auto &s = currentStore();
    const auto &c = counters_[view_];
    const auto drops = c.driverDropped ? QString::number(*c.driverDropped) : i18n::text("未知");
    const auto discarded = dropCountDisplay(c.queueDropped, c.driverDropped, i18n::text("未知"));
    const QStringList values = {
        QString::number(c.received),
        QString::number(s.stats().received),
        QString::number(s.packets().size()),
        QString::number(model_->rowCount()),
        QString::number(s.stats().overwritten),
        QString::number(c.queueDropped),
        drops,
        QString::number(s.stats().malformed),
        QString::number(double(s.estimatedBytes()) / 1048576, 'f', 1) + " MiB",
        QString::number(double(c.queuedEstimatedBytes) / 1048576, 'f', 1) + " MiB",
        QString::number(double(exporter_.referencedBytes()) / 1048576, 'f', 1) + " MiB",
        QString::number(double(selectedDetails_ ? selectedDetails_->estimatedBytes : 0) / 1048576,
                        'f', 1) +
            " MiB"};
    for (qsizetype i = 0; i < values.size(); ++i)
        if (diagnosticValues_[i]->text() != values[i])
            diagnosticValues_[i]->setText(values[i]);
    capturedLabel_->setText(QString::number(c.received));
    displayedLabel_->setText(QString::number(model_->rowCount()));
    droppedLabel_->setText(discarded.text);
    style::setFlag(droppedLabel_, "warning", discarded.warning);
    const auto recording = recording_.stats();
    recordingLabel_->setVisible(recordingSession_);
    recordingLabel_->setText(recording.failed ? i18n::text("Recording failed")
                                              : (recording_.running() ? i18n::text("Recording")
                                                                      : i18n::text("Recorded")));
    recordingLabel_->setToolTip(QString("%1 %2\n%3 %4\n%5 %6\n%7")
                                    .arg(i18n::text("Written"))
                                    .arg(recording.written)
                                    .arg(i18n::text("Queued"))
                                    .arg(recording.queued)
                                    .arg(i18n::text("Unwritten"))
                                    .arg(recording.unwritten)
                                    .arg(i18n::errorText(recording.error)));
    style::setFlag(diagnostics_, "warning", discarded.warning);
    icons::bind(diagnostics_, discarded.warning ? icons::Id::Warning : icons::Id::Diagnostic);
    setWindowTitle("EtherScope");
    modes_->setTabToolTip(1, filePath_);
    updatePresentation();
}
void MainWindow::updateButtons() {
    recordingAction_->setEnabled(!busy() && !recordingBusy() && !closing_);
    recordingSettingsAction_->setEnabled(recordingAction_->isEnabled());
    if (bpfInput_)
        bpfInput_->setReadOnly(busy() || closing_);
    if (bpfApply_)
        bpfApply_->setEnabled(!busy() && !closing_);
    start_->setEnabled(!busy() && !recordingBusy() && !discovering() && !closing_ &&
                       devices_->currentIndex() >= 0);
    stop_->setEnabled(!closing_ && (preparingFile_ || state_ == CaptureState::Starting ||
                                    state_ == CaptureState::Running));
    refresh_->setEnabled(!busy() && !discovering() && !closing_);
    devices_->setEnabled(!busy() && !discovering() && !closing_);
    modes_->setEnabled(!openingFile_ && state_ != CaptureState::Stopping && !closing_);
    open_->setEnabled(!openingFile_ && state_ != CaptureState::Stopping && !closing_);
    save_->setEnabled(!saving_ && !closing_ && !currentStore().packets().empty());
    follow_->setEnabled(view_ == 0);
    updatePresentation();
}
void MainWindow::updatePresentation() {
    if (!emptyState_)
        return;
    applicationAction_->setEnabled(bool(selected_));
    applicationAction_->setToolTip(selected_ ? i18n::text("Application analysis")
                                             : i18n::text("选择数据包后可进行应用分析"));
    bool conditions = false;
    for (auto *chip :
         {protocolChip_, icmpChip_, macChip_, ipChip_, conversationChip_, expressionChip_})
        conditions |= !chip->isHidden();
    conditionStrip_->setVisible(conditions);
    follow_->setText(i18n::text(view_ == 0 && !follow_->isChecked() ? "已暂停跟随" : "跟随"));
    emptyState_->setGeometry(table_->viewport()->rect());
    fieldEmpty_->setGeometry(fields_->viewport()->rect());
    fieldEmpty_->setVisible(!selected_);
    i18n::setLabel(fieldEmpty_, "选择数据包以查看字段和字节");
    hex_->setPlaceholderText(i18n::text("选择数据包以查看字段和字节"));
    emptyState_->setVisible(model_->rowCount() == 0);
    if (model_->rowCount())
        return;
    const bool filtered = !currentStore().packets().empty();
    const bool waiting = view_ == active_ && state_ == CaptureState::Running;
    const bool unavailable = view_ == 0 && !discovering() && devices_->count() == 0;
    QString title, hint;
    if (filtered) {
        title = "没有匹配的数据包";
        hint = "调整筛选或移除上方条件以查看数据包";
    } else if (view_ == active_ && state_ == CaptureState::Starting) {
        title = "正在准备数据源";
        hint = "连接完成后将在此显示数据包";
    } else if (view_ == active_ && state_ == CaptureState::Stopping) {
        title = "正在停止";
        hint = "正在处理已接收的数据包";
    } else if (waiting) {
        title = "正在等待数据包";
        hint = "新数据包将在此实时显示";
    } else if (unavailable) {
        title = "没有可用网卡";
        hint = "刷新接口，或打开捕获文件继续分析";
    } else {
        title = "开始一次网络观察";
        hint = "选择网卡开始捕获，或打开 PCAP / PCAPNG 文件";
    }
    i18n::setLabel(emptyTitle_, title);
    i18n::setLabel(emptyHint_, hint);
    emptyStart_->setVisible(!filtered && !waiting && !unavailable && view_ == 0 &&
                            state_ == CaptureState::Idle);
    emptyOpen_->setVisible(!filtered && !waiting && state_ == CaptureState::Idle);
    emptyRefresh_->setVisible(unavailable);
    emptyAdjust_->setVisible(filtered);
    emptyStart_->setEnabled(start_->isEnabled());
    emptyOpen_->setEnabled(open_->isEnabled());
    emptyRefresh_->setEnabled(refresh_->isEnabled());
}
void MainWindow::resetRates() {
    chart_->reset();
    chart_->setProtocols(currentStore().stats().protocols);
    lastCount_ = counters_[view_].received - counters_[view_].untimedPackets;
    lastBytes_ = counters_[view_].bytes - counters_[view_].untimedBytes;
    rateClock_.restart();
}
void MainWindow::reportError(const QString &message) {
    actionError_ = message;
    updateStatus();
}
} // namespace etherscope
