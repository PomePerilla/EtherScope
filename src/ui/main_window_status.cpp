#include "ui/main_window.h"
#include "ui/helpers.h"
#include "ui/language.h"
#include "ui/style.h"
#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableView>
#include <QTabBar>
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
    const auto &s = currentStore();
    const auto &c = counters_[view_];
    const auto drops = c.driverDropped ? QString::number(*c.driverDropped) : i18n::text("未知");
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
    const auto discarded = c.queueDropped + c.driverDropped.value_or(0);
    droppedLabel_->setText(QString::number(discarded));
    style::setFlag(droppedLabel_, "warning", discarded > 0);
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
    style::setFlag(diagnostics_, "warning", discarded > 0);
    setWindowTitle("EtherScope");
    modes_->setTabToolTip(1, filePath_);
}
void MainWindow::updateButtons() {
    recordingAction_->setEnabled(!busy() && !recording_.running() && !closing_);
    recordingSettingsAction_->setEnabled(recordingAction_->isEnabled());
    if (bpfInput_)
        bpfInput_->setReadOnly(busy() || closing_);
    if (bpfApply_)
        bpfApply_->setEnabled(!busy() && !closing_);
    start_->setEnabled(!busy() && !recording_.running() && !discovering() && !closing_ &&
                       devices_->currentIndex() >= 0);
    stop_->setEnabled(!closing_ && (preparingFile_ || state_ == CaptureState::Starting ||
                                    state_ == CaptureState::Running));
    refresh_->setEnabled(!busy() && !discovering() && !closing_);
    devices_->setEnabled(!busy() && !discovering() && !closing_);
    modes_->setEnabled(!openingFile_ && state_ != CaptureState::Stopping && !closing_);
    open_->setEnabled(!openingFile_ && state_ != CaptureState::Stopping && !closing_);
    save_->setEnabled(!saving_ && !closing_ && !currentStore().packets().empty());
    follow_->setEnabled(view_ == 0);
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
