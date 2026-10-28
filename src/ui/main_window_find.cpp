#include "ui/main_window.h"
#include "ui/find_bar.h"
#include "ui/language.h"
#include <QApplication>
#include <QAction>
#include <QCheckBox>
#include <QHeaderView>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QShortcut>
#include <QTableView>
#include <QTextBlock>
#include <QTreeWidget>
#include <QToolButton>
#include <QVBoxLayout>
namespace etherscope {
namespace {
QString fieldIdentity(QTreeWidgetItem *item) {
    if (!item)
        return {};
    return item->data(0, Qt::UserRole + 2).toString() + '/' +
           item->data(0, Qt::UserRole + 5).toString() + '/' +
           item->data(0, Qt::UserRole).toString();
}
} // namespace
void MainWindow::initializeFind() {
    find_ = new FindBar(centralWidget());
    find_->setObjectName("mainFindBar");
    static_cast<QVBoxLayout *>(centralWidget()->layout())->insertWidget(3, find_);
    readingBack_ = new QAction("后退", this);
    readingBack_->setObjectName("readingBack");
    readingForward_ = new QAction("前进", this);
    readingForward_->setObjectName("readingForward");
    readingBack_->setShortcut(QKeySequence(Qt::ALT | Qt::Key_Left));
    readingForward_->setShortcut(QKeySequence(Qt::ALT | Qt::Key_Right));
    addAction(readingBack_);
    addAction(readingForward_);
    connect(readingBack_, &QAction::triggered, this, [this] { navigateReading(false); });
    connect(readingForward_, &QAction::triggered, this, [this] { navigateReading(true); });
    auto *header = static_cast<QHBoxLayout *>(detailId_->parentWidget()->layout());
    for (auto *action : {readingForward_, readingBack_}) {
        auto *button = new QToolButton(this);
        button->setDefaultAction(action);
        button->setAccessibleName(action->text());
        header->insertWidget(0, button);
    }
    find_->addTarget({"报文列表", table_, false,
                      [this] {
                          QList<int> columns;
                          for (int i = 0; i < model_->columnCount(); ++i) {
                              const auto column = table_->horizontalHeader()->logicalIndex(i);
                              if (!table_->isColumnHidden(column))
                                  columns.append(column);
                          }
                          auto source = model_->findSource(columns);
                          const auto context = sourceContext(view_);
                          source.valid = [this, context] {
                              return context.session == view_ && sourceValid(context);
                          };
                          return source;
                      },
                      [this](const QString &key, std::size_t, std::size_t) {
                          const auto row = model_->rowForId(key.toULongLong());
                          if (row < 0)
                              return false;
                          rememberReading();
                          follow_->setChecked(false);
                          selectPacket(row);
                          table_->scrollTo(table_->currentIndex());
                          table_->setFocus();
                          return true;
                      }});
    find_->addTarget(
        {"当前字段", fields_, false,
         [this] {
             auto rows = std::make_shared<std::vector<FindDocument>>();
             for (QTreeWidgetItemIterator it(fields_); *it; ++it)
                 rows->push_back({fieldIdentity(*it), (*it)->text(0) + '\t' + (*it)->text(1), {}});
             const auto packet = selected_ ? selected_->id : 0;
             const auto context = sourceContext(view_);
             return FindSource{int(rows->size()), [rows](int i) { return (*rows)[std::size_t(i)]; },
                               [this, context, packet] {
                                   return sourceValid(context) && context.session == view_ &&
                                          selected_ && selected_->id == packet;
                               }};
         },
         [this](const QString &key, std::size_t, std::size_t) {
             for (QTreeWidgetItemIterator it(fields_); *it; ++it)
                 if (fieldIdentity(*it) == key) {
                     rememberReading();
                     for (auto *p = (*it)->parent(); p; p = p->parent())
                         p->setExpanded(true);
                     fields_->setCurrentItem(*it);
                     fields_->scrollToItem(*it);
                     fields_->setFocus();
                     return true;
                 }
             return false;
         }});
    find_->addTarget(
        {"当前报文字节", hex_, true,
         [this] {
             const auto packet = selected_;
             const auto context = sourceContext(view_);
             const auto bytes =
                 packet
                     ? std::shared_ptr<const std::vector<std::uint8_t>>(packet, &packet->raw.bytes)
                     : nullptr;
             return FindSource{packet ? 1 : 0, [bytes](int) { return FindDocument{{}, {}, bytes}; },
                               [this, packet, context] {
                                   return sourceValid(context) && context.session == view_ &&
                                          selected_ == packet;
                               }};
         },
         [this](const QString &, std::size_t offset, std::size_t length) {
             if (!selected_ || offset >= selected_->raw.bytes.size())
                 return false;
             rememberReading();
             fields_->setCurrentItem(nullptr);
             findByteRange_ = {{offset, length}};
             renderHexPage(offset);
             QTreeWidgetItem range;
             range.setData(0, Qt::UserRole, qulonglong(offset));
             range.setData(0, Qt::UserRole + 1, qulonglong(length));
             highlightBytes(&range);
             const auto block = hex_->document()->findBlockByNumber(int((offset - hexStart_) / 16));
             if (block.isValid()) {
                 QTextCursor cursor(block);
                 hex_->setTextCursor(cursor);
                 hex_->ensureCursorVisible();
             }
             hex_->setFocus();
             return true;
         }});
    auto *findAction = new QAction("查找", this);
    findAction->setObjectName("findAction");
    findAction->setShortcut(QKeySequence::Find);
    addAction(findAction);
    connect(findAction, &QAction::triggered, this,
            [this] { find_->openFor(QApplication::focusWidget()); });
    connect(qApp, &QApplication::focusChanged, this, [this, findAction](QWidget *, QWidget *now) {
        bool analysis = false;
        for (auto *widget = now; widget; widget = widget->parentWidget())
            analysis |= widget->property("analysisFindScope").toBool();
        findAction->setEnabled(!analysis);
        updateReadingActions();
    });
    auto *button = new QToolButton(this);
    button->setDefaultAction(findAction);
    header->addWidget(button);
    connect(model_, &QAbstractItemModel::modelReset, find_, &FindBar::invalidate);
    connect(model_, &QAbstractItemModel::rowsInserted, find_, &FindBar::markChanged);
    connect(model_, &QAbstractItemModel::rowsRemoved, find_, &FindBar::markChanged);
    connect(this, &MainWindow::detailsFinished, this, &MainWindow::restoreReadingDetails);
    connect(this, &MainWindow::detailsFinished, find_, &FindBar::markChanged);
    connect(&i18n::language(), &i18n::Language::changed, find_, &FindBar::invalidate);
    updateReadingActions();
    i18n::bind(find_);
    i18n::bind(this);
}
QVariantMap MainWindow::readingPosition() const {
    if (!selected_)
        return {};
    const auto c = sourceContext(view_);
    const auto top = table_->indexAt(QPoint(2, 2));
    const auto topPacket = model_->packetAt(top.row());
    return {{"session", view_},
            {"generation", qulonglong(c.generation)},
            {"packet", qulonglong(selected_->id)},
            {"column", table_->currentIndex().column()},
            {"topPacket", qulonglong(topPacket ? topPacket->id : 0)},
            {"field", fieldIdentity(fields_->currentItem())},
            {"page", qulonglong(hexStart_)},
            {"listScroll", table_->verticalScrollBar()->value()},
            {"fieldScroll", fields_->verticalScrollBar()->value()},
            {"listHorizontal", table_->horizontalScrollBar()->value()},
            {"fieldHorizontal", fields_->horizontalScrollBar()->value()},
            {"byteHorizontal", hex_->horizontalScrollBar()->value()},
            {"byteScroll", hex_->verticalScrollBar()->value()}};
}
void MainWindow::rememberReading() {
    pendingReading_.clear();
    readingHistory_[view_].remember(readingPosition());
    updateReadingActions();
}
void MainWindow::updateReadingActions() {
    if (!readingBack_)
        return;
    bool analysis = false;
    for (auto *widget = QApplication::focusWidget(); widget; widget = widget->parentWidget())
        analysis |= widget->property("analysisFindScope").toBool();
    readingBack_->setEnabled(!analysis && readingHistory_[view_].canBack());
    readingForward_->setEnabled(!analysis && readingHistory_[view_].canForward());
}
void MainWindow::navigateReading(bool forward) {
    const auto next = readingHistory_[view_].take(forward, readingPosition());
    updateReadingActions();
    if (next.isEmpty())
        return;
    if (next["session"].toInt() != view_ ||
        next["generation"].toULongLong() != sourceContext(view_).generation) {
        find_->show();
        find_->message("来源已重置，请重新定位");
        return;
    }
    const auto id = next["packet"].toULongLong();
    const auto row = model_->rowForId(id);
    if (row < 0) {
        find_->show();
        find_->message(currentStore().find(id) ? "报文已被筛选，可调整筛选后重试"
                                               : "原报文已覆盖，可跳过此历史项");
        return;
    }
    follow_->setChecked(false);
    pendingReading_ = next;
    selectPacket(row);
    table_->setCurrentIndex(model_->index(row, next["column"].toInt()));
    table_->scrollTo(table_->currentIndex());
    table_->setFocus();
    if (!detailsPending_)
        restoreReadingDetails();
}
void MainWindow::restoreReadingDetails() {
    if (pendingReading_.isEmpty() || !selected_ ||
        pendingReading_["packet"].toULongLong() != selected_->id)
        return;
    if (pendingReading_["session"].toInt() != view_ ||
        pendingReading_["generation"].toULongLong() != sourceContext(view_).generation) {
        pendingReading_.clear();
        return;
    }
    const auto state = pendingReading_;
    pendingReading_.clear();
    fields_->setCurrentItem(nullptr);
    findByteRange_.reset();
    for (QTreeWidgetItemIterator it(fields_); *it; ++it)
        if (fieldIdentity(*it) == state["field"].toString()) {
            for (auto *p = (*it)->parent(); p; p = p->parent())
                p->setExpanded(true);
            fields_->setCurrentItem(*it);
            break;
        }
    renderHexPage(state["page"].toULongLong());
    highlightBytes(fields_->currentItem(), false);
    table_->verticalScrollBar()->setValue(state["listScroll"].toInt());
    const auto top = model_->rowForId(state["topPacket"].toULongLong());
    if (top >= 0)
        table_->scrollTo(model_->index(top, 0), QAbstractItemView::PositionAtTop);
    fields_->verticalScrollBar()->setValue(state["fieldScroll"].toInt());
    hex_->verticalScrollBar()->setValue(state["byteScroll"].toInt());
    table_->horizontalScrollBar()->setValue(state["listHorizontal"].toInt());
    fields_->horizontalScrollBar()->setValue(state["fieldHorizontal"].toInt());
    hex_->horizontalScrollBar()->setValue(state["byteHorizontal"].toInt());
}
} // namespace etherscope
