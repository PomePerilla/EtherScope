#include "ui/main_window.h"
#include <QCheckBox>
#include <QAction>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QTableView>
#include "ui/helpers.h"
#include "ui/language.h"
#include <QSettings>
#include <QScreen>
#include <QSplitter>
#include <QHeaderView>
#include <QSignalBlocker>
#include <algorithm>
namespace etherscope {
void MainWindow::restoreSettings() {
    openDirectory_ = usableDirectory({});
    saveDirectory_ = openDirectory_;
    settings_->allKeys();
    if (settings_->status() != QSettings::NoError)
        return;
    setDarkTheme(settings_->value("ui/dark", true).toString() == "true");
    restoreGeometry(settings_->value("ui/geometry").toByteArray());
    if (auto *screen = QGuiApplication::screenAt(frameGeometry().center());
        screen || (screen = QGuiApplication::primaryScreen())) {
        const auto bounds = screen->availableGeometry();
        setMinimumSize(std::min(900, bounds.width()), std::min(580, bounds.height() - 32));
        resize(std::min(width(), bounds.width()), std::min(height(), bounds.height() - 32));
        move(std::clamp(x(), bounds.left(), std::max(bounds.left(), bounds.right() - width() + 1)),
             std::clamp(y(), bounds.top(), std::max(bounds.top(), bounds.bottom() - height() + 1)));
    }
    for (auto *splitter : centralWidget()->findChildren<QSplitter *>())
        splitter->restoreState(settings_->value("ui/" + splitter->objectName()).toByteArray());
    table_->horizontalHeader()->restoreState(settings_->value("ui/columns/v2").toByteArray());
    statistics_->setChecked(settings_->value("ui/statistics", false).toBool());
    chartPanel_->setVisible(statistics_->isChecked());
    addressToggle_->setChecked(settings_->value("ui/addressExpanded", false).toBool());
    keyDirectory_ = usableDirectory(settings_->value("files/keyDirectory").toString());
    recordingOptions_.directory =
        usableDirectory(settings_->value("recording/directory").toString());
    recordingOptions_.fileBytes =
        std::clamp(settings_->value("recording/fileMiB", 128).toULongLong(), 1ULL, 4096ULL) *
        1048576;
    recordingOptions_.diskBytes =
        std::clamp(settings_->value("recording/diskMiB", 1024).toULongLong(), 2ULL, 1048576ULL) *
        1048576;
    recordingOptions_.diskBytes =
        std::max(recordingOptions_.diskBytes, 2 * recordingOptions_.fileBytes);
    recordingOptions_.durationMs =
        std::clamp(settings_->value("recording/seconds", 300).toULongLong(), 1ULL, 86400ULL) * 1000;
    const auto expression = settings_->value("filter/expression").toString();
    if (expression.isEmpty() || compileDisplayFilter(expression.toStdString()).value) {
        expressionInput_->setText(expression);
        applyExpression(expression);
    }
    preferredDevice_ = settings_->value("capture/device").toString();
    successfulBpf_ = settings_->value("capture/bpf").toString();
    bpfDraft_ = successfulBpf_;
    openDirectory_ = usableDirectory(settings_->value("files/openDirectory").toString());
    saveDirectory_ = usableDirectory(settings_->value("files/saveDirectory").toString());
    bool macOk = false, ipOk = false;
    const auto md = settings_->value("filter/macDirection", 0).toInt(&macOk),
               id = settings_->value("filter/ipDirection", 0).toInt(&ipOk);
    const auto protocol = settings_->value("filter/protocol").toString();
    const auto protocolIndex = protocol.isEmpty() ? 0 : protocol_->findText(protocol);
    if (!macOk || !ipOk || md < 0 || md > 2 || id < 0 || id > 2 || protocolIndex < 0)
        return;
    auto filter = parseFilter(settings_->value("filter/mac").toString().toStdString(),
                              static_cast<Direction>(md),
                              settings_->value("filter/ip").toString().toStdString(),
                              static_cast<Direction>(id), protocol.toStdString());
    if (!filter.value)
        return;
    if (protocol == "ICMP" && settings_->contains("filter/icmpType")) {
        bool ok = false;
        const auto type = settings_->value("filter/icmpType").toInt(&ok);
        if (ok && (type == 8 || type == 0 || type == 11 || type == 3))
            filter.value->icmpType = static_cast<std::uint8_t>(type);
    }
    model_->setFilter(*filter.value);
    mac_->setText(filter.value->mac ? q(formatMac(*filter.value->mac)) : QString{});
    ip_->setText(filter.value->ip
                     ? q(formatIp(*filter.value->ip))
                     : (filter.value->ipv6 ? q(formatIpv6(*filter.value->ipv6)) : QString{}));
    macDirection_->setCurrentIndex(md);
    ipDirection_->setCurrentIndex(id);
    {
        QSignalBlocker block(protocol_);
        protocol_->setCurrentIndex(protocolIndex);
    }
    updateFilterStatus();
}
void MainWindow::saveSettings() {
    settings_->setValue("ui/dark", dark_);
    settings_->setValue("ui/geometry", saveGeometry());
    settings_->setValue("ui/columns/v2", table_->horizontalHeader()->saveState());
    settings_->setValue("ui/statistics", statistics_->isChecked());
    settings_->setValue("ui/language", i18n::language().current());
    settings_->setValue("ui/addressExpanded", addressToggle_->isChecked());
    settings_->setValue("filter/expression",
                        model_->expression() ? q(model_->expression()->source()) : QString{});
    settings_->setValue("files/keyDirectory", keyDirectory_);
    settings_->setValue("recording/directory", recordingOptions_.directory);
    settings_->setValue("recording/fileMiB", qulonglong(recordingOptions_.fileBytes / 1048576));
    settings_->setValue("recording/diskMiB", qulonglong(recordingOptions_.diskBytes / 1048576));
    settings_->setValue("recording/seconds", qulonglong(recordingOptions_.durationMs / 1000));
    for (auto *splitter : centralWidget()->findChildren<QSplitter *>())
        settings_->setValue("ui/" + splitter->objectName(), splitter->saveState());
    const auto device = devices_->currentData().toString();
    settings_->setValue("capture/device", device.isEmpty() ? preferredDevice_ : device);
    settings_->setValue("capture/bpf", successfulBpf_);
    const auto &f = model_->filter();
    settings_->setValue("filter/mac", f.mac ? q(formatMac(*f.mac)) : QString{});
    settings_->setValue("filter/ip",
                        f.ip ? q(formatIp(*f.ip)) : (f.ipv6 ? q(formatIpv6(*f.ipv6)) : QString{}));
    settings_->setValue("filter/macDirection", static_cast<int>(f.macDirection));
    settings_->setValue("filter/ipDirection", static_cast<int>(f.ipDirection));
    settings_->setValue("filter/protocol", q(f.protocol));
    if (f.protocol == "ICMP" && f.icmpType)
        settings_->setValue("filter/icmpType", int(*f.icmpType));
    else
        settings_->remove("filter/icmpType");
    settings_->setValue("files/openDirectory", openDirectory_);
    settings_->setValue("files/saveDirectory", saveDirectory_);
    settings_->sync();
}
} // namespace etherscope
