#include "ui/application_view.h"
#include "ui/find_bar.h"
#include "ui/language.h"
#include <QApplication>
#include <QComboBox>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QShortcut>
#include <QTextBlock>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <algorithm>
namespace etherscope {
void ApplicationView::initializeFind(QLayout *bar) {
    setProperty("analysisFindScope", true);
    find_ = new FindBar(this);
    find_->setObjectName("applicationFindBar");
    static_cast<QVBoxLayout *>(layout())->insertWidget(1, find_);
    back_ = new QPushButton("后退", this);
    back_->setObjectName("applicationReadingBack");
    forward_ = new QPushButton("前进", this);
    forward_->setObjectName("applicationReadingForward");
    auto *open = new QPushButton("查找", this);
    open->setObjectName("applicationFind");
    for (auto *b : {back_, forward_, open}) {
        b->setAccessibleName(b->text());
        bar->addWidget(b);
    }
    connect(back_, &QPushButton::clicked, this, [this] { navigateReading(false); });
    connect(forward_, &QPushButton::clicked, this, [this] { navigateReading(true); });
    connect(open, &QPushButton::clicked, this,
            [this] { find_->openFor(QApplication::focusWidget()); });
    auto shortcut = [this](QKeySequence sequence, auto callback) {
        auto *key = new QShortcut(sequence, this);
        key->setContext(Qt::WidgetWithChildrenShortcut);
        connect(key, &QShortcut::activated, this, callback);
    };
    shortcut(QKeySequence::Find, [this] { find_->openFor(QApplication::focusWidget()); });
    shortcut(QKeySequence(Qt::ALT | Qt::Key_Left), [this] { navigateReading(false); });
    shortcut(QKeySequence(Qt::ALT | Qt::Key_Right), [this] { navigateReading(true); });
    find_->addTarget(
        {"应用消息", list_, false,
         [this] {
             auto rows = std::make_shared<std::vector<FindDocument>>();
             rows->reserve(messages_.size());
             for (const auto &row : messages_) {
                 const auto &m = *row.message;
                 QString text = QString::fromStdString(m.protocol + " " + m.summary);
                 for (const auto &field : m.fields)
                     text += '\t' + i18n::text(QString::fromStdString(field.name)) + '\t' +
                             QString::fromStdString(applicationText(field.value));
                 rows->push_back({row.key, std::move(text), {}});
             }
             const auto epoch = bindingEpoch_;
             return FindSource{int(rows->size()), [rows](int i) { return (*rows)[std::size_t(i)]; },
                               [this, epoch] { return bindingEpoch_ == epoch; }};
         },
         [this](const QString &key, std::size_t, std::size_t) {
             auto *item = messageItems_.value(key);
             const auto row = std::find_if(messages_.begin(), messages_.end(),
                                           [&](const auto &m) { return m.key == key; });
             if (!item || row == messages_.end() || messageCounts_.value(row->base) != 1)
                 return false;
             rememberReading();
             list_->setCurrentItem(item);
             list_->scrollToItem(item);
             list_->setFocus();
             return true;
         }});
    find_->addTarget(
        {"当前字段", fields_, false,
         [this] {
             auto rows = std::make_shared<std::vector<FindDocument>>();
             for (const auto &row : fieldRows_)
                 rows->push_back({row.key,
                                  i18n::text(QString::fromStdString(row.field->name)) + '\t' +
                                      QString::fromStdString(applicationText(row.field->value)),
                                  {}});
             const auto epoch = bindingEpoch_;
             const auto key = selectedKey_;
             return FindSource{
                 int(rows->size()), [rows](int i) { return (*rows)[std::size_t(i)]; },
                 [this, epoch, key] { return bindingEpoch_ == epoch && selectedKey_ == key; }};
         },
         [this](const QString &key, std::size_t, std::size_t) {
             if (auto *item = fieldItems_.value(key)) {
                 rememberReading();
                 fields_->setCurrentItem(item);
                 fields_->scrollToItem(item);
                 fields_->setFocus();
                 return true;
             }
             return false;
         }});
    find_->addTarget(
        {"当前消息字节", bytes_, true,
         [this] {
             const auto bytes = selected_ ? selected_->bytes : nullptr;
             const auto epoch = bindingEpoch_;
             const auto key = selectedKey_;
             return FindSource{bytes ? 1 : 0, [bytes](int) { return FindDocument{{}, {}, bytes}; },
                               [this, epoch, key, bytes] {
                                   return bindingEpoch_ == epoch && selectedKey_ == key &&
                                          selected_ && selected_->bytes == bytes;
                               }};
         },
         [this](const QString &, std::size_t offset, std::size_t length) {
             if (!selected_ || !selected_->bytes || offset >= selected_->bytes->size())
                 return false;
             rememberReading();
             fields_->setCurrentItem(nullptr);
             findByteRange_ = {{offset, length}};
             page(offset);
             QList<QTextEdit::ExtraSelection> marks;
             const auto end = std::min({selected_->bytes->size(), offset + length, offset_ + 4096});
             for (auto at = offset; at < end;) {
                 const auto count = std::min<std::size_t>(16 - at % 16, end - at);
                 const auto block = bytes_->document()->findBlockByNumber(int((at - offset_) / 16));
                 if (!block.isValid())
                     break;
                 QTextEdit::ExtraSelection mark;
                 mark.cursor = QTextCursor(bytes_->document());
                 mark.cursor.setPosition(block.position() + 8 + int(at % 16) * 3);
                 mark.cursor.setPosition(mark.cursor.position() + int(count * 3 - 1),
                                         QTextCursor::KeepAnchor);
                 mark.format.setBackground(palette().highlight());
                 mark.format.setForeground(palette().highlightedText());
                 marks.append(mark);
                 at += count;
             }
             bytes_->setExtraSelections(marks);
             if (!marks.empty()) {
                 bytes_->setTextCursor(marks.front().cursor);
                 bytes_->ensureCursorVisible();
             }
             bytes_->setFocus();
             return true;
         }});
    connect(&i18n::language(), &i18n::Language::changed, find_, &FindBar::invalidate);
    updateReadingActions();
}
QVariantMap ApplicationView::readingPosition() const {
    if (!selected_)
        return {};
    auto *top = list_->itemAt(2, 2);
    auto *fieldTop = fields_->itemAt(2, 2);
    return {{"epoch", qulonglong(bindingEpoch_)},
            {"message", selectedKey_},
            {"field", fieldKey_},
            {"topMessage", top ? top->data(0, Qt::UserRole + 7) : QVariant{}},
            {"topOffset", top ? list_->visualItemRect(top).top() : 0},
            {"topField", fieldTop ? fieldTop->data(0, Qt::UserRole + 7) : QVariant{}},
            {"fieldOffset", fieldTop ? fields_->visualItemRect(fieldTop).top() : 0},
            {"page", qulonglong(offset_)},
            {"packet", packets_->currentData()},
            {"listScroll", list_->verticalScrollBar()->value()},
            {"fieldScroll", fields_->verticalScrollBar()->value()},
            {"listHorizontal", list_->horizontalScrollBar()->value()},
            {"fieldHorizontal", fields_->horizontalScrollBar()->value()},
            {"byteHorizontal", bytes_->horizontalScrollBar()->value()},
            {"byteScroll", bytes_->verticalScrollBar()->value()},
            {"fieldHelp", fieldHelpToggle_->isChecked()},
            {"statusHelp", state_->isChecked()}};
}
void ApplicationView::rememberReading() {
    pendingReading_.clear();
    history_.remember(readingPosition());
    updateReadingActions();
}
void ApplicationView::updateReadingActions() {
    if (!back_)
        return;
    back_->setEnabled(history_.canBack());
    forward_->setEnabled(history_.canForward());
}
void ApplicationView::navigateReading(bool forward) {
    const auto next = history_.take(forward, readingPosition());
    updateReadingActions();
    if (next.isEmpty())
        return;
    const auto key = next["message"].toString();
    const auto row = std::find_if(messages_.begin(), messages_.end(),
                                  [&](const auto &m) { return m.key == key; });
    if (next["epoch"].toULongLong() != bindingEpoch_ || row == messages_.end() ||
        messageCounts_.value(row->base) != 1) {
        find_->show();
        find_->message("目标已移出当前结果，可跳过此历史项");
        return;
    }
    auto *item = messageItems_.value(key);
    if (!item)
        return;
    pendingReading_ = next;
    if (list_->currentItem() == item)
        restoreReadingDetails();
    else
        list_->setCurrentItem(item);
}
void ApplicationView::restoreReadingDetails() {
    if (pendingReading_.isEmpty() || pendingReading_["message"].toString() != selectedKey_)
        return;
    const auto p = pendingReading_;
    pendingReading_.clear();
    findByteRange_.reset();
    fields_->setCurrentItem(fieldItems_.value(p["field"].toString()));
    page(p["page"].toULongLong());
    packets_->setCurrentIndex(packets_->findData(p["packet"]));
    locate_->setEnabled(navigationEnabled_ && packets_->currentIndex() >= 0);
    list_->verticalScrollBar()->setValue(p["listScroll"].toInt());
    fields_->verticalScrollBar()->setValue(p["fieldScroll"].toInt());
    bytes_->verticalScrollBar()->setValue(p["byteScroll"].toInt());
    auto restoreAnchor = [&](QTreeWidget *tree, QTreeWidgetItem *item, int offset) {
        if (item) {
            tree->scrollToItem(item, QAbstractItemView::PositionAtTop);
            tree->verticalScrollBar()->setValue(tree->verticalScrollBar()->value() - offset);
        }
    };
    restoreAnchor(list_, messageItems_.value(p["topMessage"].toString()), p["topOffset"].toInt());
    restoreAnchor(fields_, fieldItems_.value(p["topField"].toString()), p["fieldOffset"].toInt());
    list_->horizontalScrollBar()->setValue(p["listHorizontal"].toInt());
    fields_->horizontalScrollBar()->setValue(p["fieldHorizontal"].toInt());
    bytes_->horizontalScrollBar()->setValue(p["byteHorizontal"].toInt());
    fieldHelpToggle_->setChecked(p["fieldHelp"].toBool());
    state_->setChecked(p["statusHelp"].toBool());
}
} // namespace etherscope
