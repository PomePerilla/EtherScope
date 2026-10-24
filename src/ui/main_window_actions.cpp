#include "ui/main_window.h"
#include "ui/analysis_dock.h"
#include "ui/filter_chip.h"
#include "ui/helpers.h"
#include "ui/language.h"
#include "ui/learning.h"
#include "ui/tcp_dialog.h"
#include <QCheckBox>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDialog>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScopedValueRollback>
#include <QShortcut>
#include <QTableView>
#include <QToolButton>
#include <QToolTip>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <algorithm>

namespace etherscope {
namespace {
QString expressionFor(const Packet &p, const QString &key) {
    std::optional<ApplicationValue> value;
    if (key == "ip.src" && p.sourceIp) value = formatIp(*p.sourceIp);
    if (key == "ip.dst" && p.destinationIp) value = formatIp(*p.destinationIp);
    if (key == "ipv6.src" && p.sourceIpv6) value = formatIpv6(*p.sourceIpv6);
    if (key == "ipv6.dst" && p.destinationIpv6) value = formatIpv6(*p.destinationIpv6);
    if (key == "eth.src" && p.sourceMac) value = formatMac(*p.sourceMac);
    if (key == "eth.dst" && p.destinationMac) value = formatMac(*p.destinationMac);
    if (p.tcp) {
        if (key == "tcp.srcport") value = std::uint64_t(p.tcp->sourcePort);
        if (key == "tcp.dstport") value = std::uint64_t(p.tcp->destinationPort);
        if (key == "tcp.flags") value = std::uint64_t(p.tcp->flags);
    }
    if (p.udp) {
        if (key == "udp.srcport") value = std::uint64_t(p.udp->sourcePort);
        if (key == "udp.dstport") value = std::uint64_t(p.udp->destinationPort);
    }
    if ((key == "icmp.type" || key == "icmpv6.type") && p.icmpType)
        value = std::uint64_t(*p.icmpType);
    return value ? learning::fieldPredicate(key, *value) : QString{};
}
QString stateCaption(const FilterSpec &f, const QString &expression) {
    QStringList parts;
    if (!f.protocol.empty()) parts << q(f.protocol);
    if (f.mac) parts << q(formatMac(*f.mac));
    if (f.ip) parts << q(formatIp(*f.ip));
    if (f.ipv6) parts << q(formatIpv6(*f.ipv6));
    if (f.icmpType) parts << "ICMP " + QString::number(*f.icmpType);
    if (f.tcpConversationId) parts << i18n::text("会话 %1").arg(*f.tcpConversationId);
    if (!expression.isEmpty()) parts << expression;
    return parts.isEmpty() ? i18n::text("全部协议") : parts.join(" AND ");
}
} // namespace
MainWindow::DisplayState MainWindow::displayState() const {
    return {model_->filter(), model_->expression() ? q(model_->expression()->source()) : QString{},
            sourceContext(view_)};
}
void MainWindow::rememberFilter(const FilterSpec &filter, const QString &expression) {
    if (!historyReady_ || restoringFilter_)
        return;
    const auto current = displayState();
    const DisplayState next{filter, expression, current.source};
    if (current == next)
        return;
    filterUndo_.push_back(current);
    if (filterUndo_.size() > 20) filterUndo_.erase(filterUndo_.begin());
    std::erase(filterRecent_, next);
    filterRecent_.insert(filterRecent_.begin(), next);
    if (filterRecent_.size() > 20) filterRecent_.pop_back();
    refreshFilterHistory();
}
void MainWindow::restoreFilter(const DisplayState &state) {
    if (state.source.session != view_ || !sourceValid(state.source)) {
        reportError("筛选来源已失效");
        return;
    }
    if (!state.expression.isEmpty() && !compileDisplayFilter(state.expression.toStdString()).value)
        return;
    QScopedValueRollback<bool> restoring(restoringFilter_, true);
    applyExpression(state.expression);
    commitFilter(state.filter);
    syncFilterInputs();
    refreshFilterHistory();
}
void MainWindow::applyQuickFilter(const QString &predicate, bool unique) {
    const auto state = displayState();
    auto expression = unique || state.expression.isEmpty()
                          ? predicate : "(" + state.expression + ") and (" + predicate + ")";
    auto filter = unique ? FilterSpec{} : state.filter;
    if (predicate.startsWith("tcp.stream == ")) {
        // Conversation IDs must be cleared by setStore()/clear(), unlike reusable address predicates.
        bool ok = false;
        const auto conversation = predicate.mid(14).toULongLong(&ok);
        if (!ok || !conversation) return;
        if (unique) {
            filter.protocol = "TCP";
            filter.icmpType.reset();
        }
        filter.tcpConversationId = conversation;
        expression = unique ? QString{} : state.expression;
    }
    if (!expression.isEmpty() && !compileDisplayFilter(expression.toStdString()).value) {
        reportError("生成的筛选表达式无效");
        return;
    }
    rememberFilter(filter, expression);
    QScopedValueRollback<bool> restoring(restoringFilter_, true);
    applyExpression(expression);
    commitFilter(filter);
    syncFilterInputs();
    expressionAction_->setChecked(!expression.isEmpty());
}
void MainWindow::refreshFilterHistory() {
    if (!undoFilter_)
        return;
    undoFilter_->setEnabled(!filterUndo_.empty());
    recentFilters_->clear();
    if (filterRecent_.empty())
        recentFilters_->addAction(i18n::text("暂无最近筛选"))->setEnabled(false);
    for (const auto &state : filterRecent_) {
        const auto full = stateCaption(state.filter, state.expression);
        auto *action = recentFilters_->addAction(
            fontMetrics().elidedText(full, Qt::ElideMiddle, 420).replace("&", "&&"));
        const bool valid = state.source.session == view_ && sourceValid(state.source);
        action->setEnabled(valid);
        action->setToolTip(valid ? full : i18n::text("筛选来源已失效"));
        connect(action, &QAction::triggered, this, [this, state] {
            if (state.source.session != view_ || !sourceValid(state.source)) {
                reportError("筛选来源已失效");
                return;
            }
            rememberFilter(state.filter, state.expression);
            restoreFilter(state);
        });
    }
}
QMenu *MainWindow::packetMenu(const QModelIndex &index) {
    const auto packet = model_->packetAt(index.row());
    auto *menu = new QMenu(table_);
    menu->setObjectName("packetContextMenu");
    if (!packet) return menu;
    const auto context = sourceContext(view_);
    const auto valid = [this, context, packet] {
        const bool ok = view_ == context.session && sourceValid(context) &&
                        storeFor(context.session).find(packet->id) == packet;
        if (!ok) {
            reportError("操作目标已失效，请重新选择报文");
            QToolTip::showText(QCursor::pos(), i18n::text("操作目标已失效，请重新选择报文"), table_);
        }
        return ok;
    };
    const auto cell = index.data().toString();
    QStringList cells;
    for (int visual = 0; visual < model_->columnCount(); ++visual) {
        const auto column = table_->horizontalHeader()->logicalIndex(visual);
        if (!table_->isColumnHidden(column))
            cells << model_->index(index.row(), column).data().toString();
    }
    auto add = [&](const char *caption, const char *name, auto callback, bool enabled = true) {
        auto *action = menu->addAction(i18n::text(caption));
        action->setObjectName(name);
        action->setEnabled(enabled);
        connect(action, &QAction::triggered, menu, [valid, callback] { if (valid()) callback(); });
    };
    add("复制当前单元格", "copyPacketCell", [cell] { qApp->clipboard()->setText(cell); });
    add("复制整行", "copyPacketRow", [text = cells.join('\t')] { qApp->clipboard()->setText(text); });
    menu->addSeparator();
    auto filter = [&](const char *caption, const char *name, const QString &predicate) {
        auto *sub = menu->addMenu(i18n::text(caption));
        sub->setObjectName(name);
        sub->setEnabled(!predicate.isEmpty());
        sub->setToolTipsVisible(true);
        for (bool unique : {true, false}) {
            auto *action = sub->addAction(i18n::text(unique ? "作为唯一筛选" : "加入当前筛选"));
            action->setObjectName(QString(name) + (unique ? "Only" : "Add"));
            action->setToolTip(predicate);
            connect(action, &QAction::triggered, menu, [this, predicate, unique, valid] {
                if (valid()) applyQuickFilter(predicate, unique);
            });
        }
    };
    auto src = expressionFor(*packet, packet->sourceIp ? "ip.src" : "ipv6.src");
    auto dst = expressionFor(*packet, packet->destinationIp ? "ip.dst" : "ipv6.dst");
    if (src.isEmpty()) src = expressionFor(*packet, "eth.src");
    if (dst.isEmpty()) dst = expressionFor(*packet, "eth.dst");
    filter("按源地址筛选", "packetSourceFilter", src);
    filter("按目的地址筛选", "packetDestinationFilter", dst);
    auto protocol = q(packet->protocol).toLower();
    if (protocol == "ethernet") protocol = "eth";
    if (protocol == "ipv4") protocol = "ip";
    filter("按协议筛选", "packetProtocolFilter",
           compileDisplayFilter(protocol.toStdString()).value ? protocol : QString{});
    filter("按 TCP 会话筛选", "packetConversationFilter",
           packet->tcpConversationId ? QString("tcp.stream == %1").arg(packet->tcpConversationId)
                                     : QString{});
    menu->addSeparator();
    add("查看当前 TCP 会话", "packetTcpAnalysis", [this, packet] {
        selectPacket(model_->rowForId(packet->id));
        showTcpConversations();
        bindTcpSource();
        tcpDialog_->selectConversation(packet->tcpConversationId);
    }, packet->tcpConversationId != 0);
    add("应用分析", "packetApplicationAnalysis", [this, packet] {
        selectPacket(model_->rowForId(packet->id));
        showApplicationAnalysis();
    });
    return menu;
}
QMenu *MainWindow::fieldMenu(QTreeWidgetItem *item) {
    auto *menu = new QMenu(fields_);
    menu->setObjectName("fieldContextMenu");
    if (!item || !selected_) return menu;
    const auto packet = selected_;
    const auto context = sourceContext(view_);
    const auto value = item->text(1), name = item->text(0);
    const auto offset = item->data(0, Qt::UserRole).toULongLong();
    const auto length = item->data(0, Qt::UserRole + 1).toULongLong();
    const auto key = item->data(0, Qt::UserRole + 5).toString();
    auto predicate = expressionFor(*packet, key);
    if (key == "dns.qry.name")
        predicate = learning::fieldPredicate(key, item->data(0, Qt::UserRole + 4).toString().toStdString());
    const auto valid = [this, packet, context] {
        if (view_ == context.session && sourceValid(context) &&
            storeFor(context.session).find(packet->id) == packet) return true;
        reportError("操作目标已失效，请重新选择报文");
        QToolTip::showText(QCursor::pos(), i18n::text("操作目标已失效，请重新选择报文"), fields_);
        return false;
    };
    auto add = [&](const char *caption, const char *id, auto callback, bool enabled = true) {
        auto *action = menu->addAction(i18n::text(caption));
        action->setObjectName(id);
        action->setEnabled(enabled);
        connect(action, &QAction::triggered, menu, [valid, callback] { if (valid()) callback(); });
    };
    add("复制值", "copyFieldValue", [value] { qApp->clipboard()->setText(value); });
    add("复制字段和值", "copyFieldPair", [name, value] { qApp->clipboard()->setText(name + '\t' + value); });
    const bool bytesValid = length && offset <= packet->raw.bytes.size() &&
                            length <= packet->raw.bytes.size() - offset;
    add("复制对应字节", "copyFieldBytes", [packet, offset, length] {
        const QByteArray bytes(reinterpret_cast<const char *>(packet->raw.bytes.data() + offset),
                               qsizetype(length));
        qApp->clipboard()->setText(QString::fromLatin1(bytes.toHex(' ')));
    }, bytesValid);
    for (bool unique : {true, false})
        add(unique ? "作为唯一筛选" : "加入当前筛选", unique ? "fieldFilterOnly" : "fieldFilterAdd",
            [this, predicate, unique] { applyQuickFilter(predicate, unique); }, !predicate.isEmpty());
    return menu;
}
void MainWindow::initializeInteractions() {
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    fields_->setContextMenuPolicy(Qt::CustomContextMenu);
    auto showMenu = [](QMenu *menu, const QPoint &position) {
        QObject::connect(menu, &QMenu::aboutToHide, menu, &QObject::deleteLater);
        menu->popup(position);
    };
    connect(table_, &QTableView::customContextMenuRequested, this, [this, showMenu](QPoint position) {
        const auto index = position.x() < 0 ? table_->currentIndex() : table_->indexAt(position);
        if (!index.isValid()) return;
        selectPacket(index.row());
        if (view_ == 0) follow_->setChecked(false);
        showMenu(packetMenu(index), table_->viewport()->mapToGlobal(
                      position.x() < 0 ? table_->visualRect(index).center() : position));
    });
    connect(fields_, &QTreeWidget::customContextMenuRequested, this, [this, showMenu](QPoint position) {
        auto *item = position.x() < 0 ? fields_->currentItem() : fields_->itemAt(position);
        if (!item) return;
        fields_->setCurrentItem(item);
        showMenu(fieldMenu(item), fields_->viewport()->mapToGlobal(
                      position.x() < 0 ? fields_->visualItemRect(item).center() : position));
    });
    auto copy = [this](QWidget *widget, auto callback) {
        auto *shortcut = new QShortcut(QKeySequence::Copy, widget);
        shortcut->setContext(Qt::WidgetWithChildrenShortcut);
        connect(shortcut, &QShortcut::activated, this, callback);
    };
    copy(table_, [this] {
        std::unique_ptr<QMenu> menu(packetMenu(table_->currentIndex()));
        if (auto *action = menu->findChild<QAction *>("copyPacketCell")) action->trigger();
    });
    copy(fields_, [this] {
        std::unique_ptr<QMenu> menu(fieldMenu(fields_->currentItem()));
        if (auto *action = menu->findChild<QAction *>("copyFieldValue")) action->trigger();
    });
    for (auto *widget : {static_cast<QWidget *>(table_), static_cast<QWidget *>(fields_)}) {
        for (auto key : {QKeySequence(Qt::SHIFT | Qt::Key_F10), QKeySequence(Qt::Key_Menu)}) {
            auto *shortcut = new QShortcut(key, widget);
            shortcut->setContext(Qt::WidgetWithChildrenShortcut);
            connect(shortcut, &QShortcut::activated, this, [this, widget] {
                if (widget == table_) emit table_->customContextMenuRequested(QPoint(-1, -1));
                else emit fields_->customContextMenuRequested(QPoint(-1, -1));
            });
        }
    }
    connect(undoFilter_, &QAction::triggered, this, [this] {
        if (filterUndo_.empty()) return;
        const auto state = filterUndo_.back();
        filterUndo_.pop_back();
        restoreFilter(state);
    });
    connect(recentFilters_, &QMenu::aboutToShow, this, &MainWindow::refreshFilterHistory);
    connect(fields_, &QTreeWidget::currentItemChanged, this, &MainWindow::updateFieldHelp);
    connect(fieldHelpToggle_, &QPushButton::toggled, this, [this](bool expanded) {
        fieldHelp_->setVisible(expanded);
        updateFieldHelp();
    });
    refreshFilterHistory();
}
void MainWindow::updateFieldHelp() {
    const auto *item = fields_->currentItem();
    fieldHelp_->setText(item ? learning::fieldExplanation(
                                  item->data(0, Qt::UserRole + 5).toString(), item->text(1))
                            : i18n::text("选择字段以查看说明"));
}
void MainWindow::showExpressionHelp() {
    auto *dialog = new QDialog(this);
    dialog->setObjectName("expressionHelpDialog");
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle("显示表达式帮助");
    auto *layout = new QVBoxLayout(dialog);
    auto *hint = new QLabel("显示表达式只改变当前列表；BPF 决定捕获哪些报文。应用分析未完成时，相关字段可能未知。", dialog);
    hint->setWordWrap(true);
    layout->addWidget(hint);
    for (const auto &example : {"tcp", "ip.addr == 192.0.2.1", "ipv6.addr == 2001:db8::1",
                                "tcp.port == 443", "packet.error or packet.warning",
                                "dns.qry.name contains \"example\"", "http.host contains \"example\"",
                                "tls.sni contains \"example\""}) {
        auto *button = new QPushButton(example, dialog);
        button->setProperty("expressionExample", true);
        layout->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this, example] {
            expressionAction_->setChecked(true);
            expressionInput_->setText(example);
            expressionInput_->setFocus();
        });
    }
    auto *close = new QPushButton("关闭", dialog);
    connect(close, &QPushButton::clicked, dialog, &QDialog::close);
    layout->addWidget(close);
    i18n::bind(dialog);
    dialog->resize(540, 420);
    dialog->show();
}
void MainWindow::showAnalysisHelp(AnalysisStatus status) {
    if (status == AnalysisStatus::MissingKeys) {
        findChild<QAction *>("tlsKeyLogOpen")->trigger();
    } else if (status == AnalysisStatus::Incomplete || status == AnalysisStatus::Limited ||
               status == AnalysisStatus::Pending) {
        expressionAction_->setChecked(true);
        expressionInput_->setFocus();
    } else {
        hex_->setFocus();
    }
}
} // namespace etherscope
