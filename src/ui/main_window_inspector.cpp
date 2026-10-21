#include "ui/main_window.h"
#include "ui/helpers.h"
#include "ui/language.h"
#include <QAction>
#include <QSettings>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QTableView>
#include <QTextBlock>
#include <QTreeWidget>
#include <QFontDatabase>
#include <algorithm>

namespace etherscope {
namespace {
QString fieldText(const std::string &value) {
    auto text = q(value);
    if (text == "未捕获或无法确认，不作推断")
        return "-";
    return i18n::text(text.replace("（捕获内容）", "")
                          .replace("（未验证）", "")
                          .replace("（未解密）", "")
                          .replace("; 不递归解析", ""));
}
QString warningText(const std::string &value) {
    const auto text = q(value);
    if (text.startsWith("ESP "))
        return "ESP";
    if (text.startsWith("有效载荷长度为 0"))
        return "零长度载荷";
    if (text.startsWith("邻居发现报文"))
        return "NDP 首部异常";
    if (text.startsWith("不支持的 IPv6"))
        return "未知协议";
    return text.section(";", 0, 0);
}
} // namespace
void MainWindow::showDetails() {
    const auto packetAtRow = model_->packetAt(table_->currentIndex().row());
    if (packetAtRow && packetAtRow == selected_)
        return;
    detailTimer_.stop();
    fieldItems_.clear();
    selectedDetails_.reset();
    details_.cancel();
    detailsPending_ = false;
    selected_ = packetAtRow;
    QSignalBlocker block(fields_);
    fields_->clear();
    hex_->setExtraSelections({});
    hex_->clear();
    hexPager_->hide();
    hexStart_ = 0;
    if (!selected_) {
        for (auto *label :
             {detailId_, detailProtocol_, detailCaptured_, detailOriginal_, detailIssues_})
            i18n::setLabel(label, {});
        detailIssues_->setToolTip({});
        return;
    }
    const auto &packet = *selected_;
    detailId_->setText(QString("#%1").arg(packet.id));
    i18n::setLabel(detailProtocol_, q(packet.protocol));
    detailCaptured_->setText(QString("%1 B").arg(packet.raw.bytes.size()));
    detailOriginal_->setText(QString("%1 B").arg(packet.raw.originalLength));
    QStringList issues;
    if (!packet.error.empty())
        issues << q(packet.error);
    for (const auto &warning : packet.warnings)
        issues << warningText(warning);
    i18n::setLabel(detailIssues_, issues.isEmpty() ? QString{} : issues.front());
    for (auto &issue : issues)
        issue = i18n::text(issue);
    detailIssues_->setToolTip(issues.join("\n"));
    detailsPending_ = true;
    detailRequest_ = details_.request(selected_);
    renderHexPage(0);
}
void MainWindow::fillDetails() {
    QSignalBlocker block(fields_);
    QElapsedTimer elapsed;
    elapsed.start();
    while (!fieldItems_.empty() && elapsed.nsecsElapsed() < 2000000) {
        const auto entry = fieldItems_.back();
        fieldItems_.pop_back();
        const auto &field = *entry.field;
        auto *item =
            entry.parent ? new QTreeWidgetItem(entry.parent) : new QTreeWidgetItem(fields_);
        item->setText(0, i18n::text(q(field.name)));
        item->setText(1, fieldText(field.value));
        item->setToolTip(0, item->text(0));
        item->setToolTip(1, item->text(1));
        item->setData(0, Qt::UserRole + 3, q(field.name));
        item->setData(0, Qt::UserRole + 4, q(field.value));
        const auto name = q(field.name);
        if (name.contains("地址") || name.contains("MAC") || q(field.value).startsWith("0x"))
            item->setFont(1, QFontDatabase::systemFont(QFontDatabase::FixedFont));
        item->setData(0, Qt::UserRole, QVariant::fromValue<qulonglong>(field.offset));
        item->setData(0, Qt::UserRole + 1, QVariant::fromValue<qulonglong>(field.length));
        const auto path =
            (entry.parent ? entry.parent->data(0, Qt::UserRole + 2).toString() : QString{}) + "/" +
            name;
        item->setData(0, Qt::UserRole + 2, path);
        item->setExpanded(!collapsedFields_.contains(path));
        for (auto child = field.children.rbegin(); child != field.children.rend(); ++child)
            fieldItems_.push_back({item, &*child});
    }
    if (fieldItems_.empty()) {
        detailTimer_.stop();
        detailsPending_ = false;
        emit detailsFinished(detailRequest_);
    }
}
void MainWindow::renderHexPage(std::size_t start) {
    if (!selected_)
        return;
    const auto &bytes = selected_->raw.bytes;
    hexStart_ = bytes.empty() ? 0
                              : std::min(start / hexPageSize_, (bytes.size() - 1) / hexPageSize_) *
                                    hexPageSize_;
    const auto end = std::min(bytes.size(), hexStart_ + hexPageSize_);
    QString text;
    text.reserve(static_cast<qsizetype>((end - hexStart_) * 5));
    for (std::size_t i = hexStart_; i < end; i += 16) {
        text += QString("%1  ").arg(static_cast<qulonglong>(i), 6, 16, QChar('0'));
        for (std::size_t j = 0; j < 16; ++j)
            text += i + j < end ? QString("%1 ").arg(bytes[i + j], 2, 16, QChar('0')) : "   ";
        text += "  ";
        for (std::size_t j = 0; j < 16 && i + j < end; ++j) {
            auto c = bytes[i + j];
            text += c >= 32 && c < 127 ? QChar(c) : QChar('.');
        }
        text += '\n';
    }
    hex_->setPlainText(text);
    i18n::setLabel(byteRange_, "字节 %1-%2 / %3",
                   {QString::number(hexStart_), QString::number(end ? end - 1 : 0),
                    QString::number(bytes.size())});
    previousBytes_->setEnabled(hexStart_ > 0);
    nextBytes_->setEnabled(end < bytes.size());
    hexPager_->setVisible(bytes.size() > hexPageSize_);
}
void MainWindow::retranslate() {
    for (auto *action : findChildren<QAction *>())
        if (action->objectName().startsWith("language_")) {
            QSignalBlocker block(action);
            action->setChecked(action->data().toString() == i18n::language().current());
        }
    settings_->setValue("ui/language", i18n::language().current());
    settings_->sync();
    updateFilterStatus();
    updateStatus();
    chart_->update();
    for (QTreeWidgetItemIterator item(fields_); *item; ++item) {
        (*item)->setText(0, i18n::text((*item)->data(0, Qt::UserRole + 3).toString()));
        (*item)->setText(1, fieldText((*item)->data(0, Qt::UserRole + 4).toString().toStdString()));
        (*item)->setToolTip(0, (*item)->text(0));
        (*item)->setToolTip(1, (*item)->text(1));
    }
    if (selected_) {
        QStringList issues;
        if (!selected_->error.empty())
            issues << i18n::text(q(selected_->error));
        for (const auto &warning : selected_->warnings)
            issues << i18n::text(warningText(warning));
        detailIssues_->setToolTip(issues.join("\n"));
    }
}
void MainWindow::highlightBytes(QTreeWidgetItem *item, bool locate) {
    QList<QTextEdit::ExtraSelection> selections;
    if (item && selected_) {
        auto offset = item->data(0, Qt::UserRole).toULongLong(),
             length = item->data(0, Qt::UserRole + 1).toULongLong();
        auto end = std::min<qulonglong>(selected_->raw.bytes.size(), offset + length);
        if (locate && length && offset < selected_->raw.bytes.size() &&
            (offset < hexStart_ || offset >= hexStart_ + hexPageSize_))
            renderHexPage(static_cast<std::size_t>(offset));
        end = std::min<qulonglong>(end, hexStart_ + hexPageSize_);
        for (auto o = std::max<qulonglong>(offset, hexStart_); o < end;) {
            const auto block =
                hex_->document()->findBlockByNumber(static_cast<int>((o - hexStart_) / 16));
            if (!block.isValid())
                break;
            auto n = std::min<qulonglong>(end - o, 16 - o % 16);
            QTextEdit::ExtraSelection s;
            s.cursor = QTextCursor(hex_->document());
            s.cursor.setPosition(block.position() + 8 + static_cast<int>(o % 16) * 3);
            s.cursor.setPosition(s.cursor.position() + static_cast<int>(n) * 3 - 1,
                                 QTextCursor::KeepAnchor);
            s.format.setBackground(QColor("#356ed5"));
            s.format.setForeground(Qt::white);
            selections.push_back(s);
            o += n;
        }
    }
    hex_->setExtraSelections(selections);
    if (!selections.empty()) {
        hex_->setTextCursor(selections.front().cursor);
        hex_->ensureCursorVisible();
    }
}
} // namespace etherscope
