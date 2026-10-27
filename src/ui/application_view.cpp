#include "ui/application_view.h"
#include "ui/language.h"
#include "ui/style.h"
#include "ui/helpers.h"
#include "ui/icons.h"
#include "ui/learning.h"
#include "ui/flow_layout.h"
#include <QResizeEvent>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QShortcut>
#include <QToolTip>
#include <QComboBox>
#include <QElapsedTimer>
#include <QFontDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTextBlock>
#include <QTextCursor>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace etherscope {
namespace {
QString statusText(AnalysisStatus status) {
    switch (status) {
    case AnalysisStatus::Pending:
        return i18n::text("Pending analysis");
    case AnalysisStatus::Complete:
        return i18n::text("Complete");
    case AnalysisStatus::Incomplete:
        return i18n::text("Incomplete");
    case AnalysisStatus::Limited:
        return i18n::text("Limit reached");
    case AnalysisStatus::MissingKeys:
        return i18n::text("Missing keys");
    case AnalysisStatus::Unsupported:
        return i18n::text("Unsupported");
    case AnalysisStatus::AuthenticationFailed:
        return i18n::text("Authentication failed");
    }
    return {};
}
} // namespace
ApplicationView::ApplicationView(QWidget *parent) : QWidget(parent) {
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(4);
    auto *bar = new FlowLayout;
    sources_ = new QComboBox(this);
    sources_->setObjectName("applicationDataSource");
    sources_->addItems({"All sources", "Original", "Reassembled", "Decrypted"});
    bar->addWidget(sources_);
    packets_ = new QComboBox(this);
    packets_->setObjectName("applicationPackets");
    bar->addWidget(packets_);
    state_ = new QPushButton(this);
    state_->setObjectName("applicationState");
    state_->setCheckable(true);
    state_->setProperty("statusBadge", true);
    state_->setToolTip("查看状态说明");
    state_->setAccessibleName("查看状态说明");
    bar->addWidget(state_);
    auto *locate = new QPushButton("定位", this);
    locate_ = locate;
    locate_->setObjectName("applicationLocate");
    icons::bind(locate, icons::Id::Locate);
    bar->addWidget(locate);
    fieldHelpToggle_ = new QPushButton("字段说明", this);
    fieldHelpToggle_->setObjectName("applicationFieldHelpToggle");
    fieldHelpToggle_->setCheckable(true);
    icons::bind(fieldHelpToggle_, icons::Id::Info);
    fieldHelpToggle_->setAccessibleName("字段说明");
    layout->addLayout(bar);
    selectionHint_ = new QLabel(this);
    selectionHint_->setObjectName("applicationSelectionHint");
    selectionHint_->setWordWrap(true);
    selectionHint_->hide();
    layout->addWidget(selectionHint_);
    auto *splitter = new QSplitter(Qt::Vertical, this);
    list_ = new QTreeWidget(splitter);
    list_->setObjectName("applicationMessages");
    list_->setHeaderLabels({"协议", "方向", "摘要", "状态"});
    list_->setUniformRowHeights(true);
    list_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    list_->setColumnWidth(0, 75);
    list_->setColumnWidth(1, 90);
    list_->setColumnWidth(2, 350);
    auto *lower = new QSplitter(Qt::Horizontal, splitter);
    lower_ = lower;
    auto *fieldPanel = new QWidget(lower);
    auto *fieldLayout = new QVBoxLayout(fieldPanel);
    fieldLayout->setContentsMargins(0, 0, 0, 0);
    fieldLayout->setSpacing(0);
    auto *fieldHeader = new QHBoxLayout;
    auto *fieldTitle = new QLabel("字段", fieldPanel);
    fieldTitle->setObjectName("panelTitle");
    fieldHeader->addWidget(fieldTitle, 1);
    fieldHeader->addWidget(fieldHelpToggle_);
    fieldLayout->addLayout(fieldHeader);
    fields_ = new QTreeWidget(fieldPanel);
    fields_->setObjectName("applicationFields");
    fields_->setHeaderLabels({"字段", "值"});
    fields_->setUniformRowHeights(true);
    fields_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    fields_->setColumnWidth(0, 180);
    fieldLayout->addWidget(fields_, 1);
    bytes_ = new QPlainTextEdit(lower);
    bytes_->setObjectName("applicationBytes");
    bytes_->setReadOnly(true);
    bytes_->setLineWrapMode(QPlainTextEdit::NoWrap);
    bytes_->setFont(style::dataFont());
    splitter->setObjectName("applicationContentSplitter");
    splitter->setSizes({210, 390});
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 1);
    layout->addWidget(splitter, 1);
    pager_ = new QWidget(this);
    pager_->setObjectName("applicationBytePager");
    auto *pager = new QHBoxLayout(pager_);
    pager->setContentsMargins(0, 0, 0, 0);
    auto *previous = previous_ = new QPushButton("上一页", pager_);
    previous_->setObjectName("applicationPreviousPage");
    auto *next = next_ = new QPushButton("下一页", pager_);
    next_->setObjectName("applicationNextPage");
    page_ = new QLabel(this);
    pager->addWidget(previous);
    pager->addWidget(page_, 1);
    pager->addWidget(next);
    layout->addWidget(pager_);
    pager_->hide();
    fieldHelp_ = new ExplanationText(this);
    fieldHelp_->setObjectName("applicationFieldExplanation");
    fieldHelpArea_ = explanationArea(fieldHelp_, fieldPanel);
    fieldLayout->addWidget(fieldHelpArea_);
    statusHelp_ = new ExplanationText(this);
    statusHelp_->setObjectName("analysisStatusExplanation");
    statusHelpPanel_ = new QWidget(this);
    auto *statusLayout = new QVBoxLayout(statusHelpPanel_);
    statusLayout->setContentsMargins(0, 0, 0, 0);
    statusLayout->setSpacing(0);
    statusHelpArea_ = explanationArea(statusHelp_, statusHelpPanel_);
    statusHelpArea_->show();
    statusLayout->addWidget(statusHelpArea_);
    nextStep_ = new QPushButton("下一步", this);
    nextStep_->setObjectName("analysisNextStep");
    auto *statusActions = new QHBoxLayout;
    statusActions->addStretch();
    statusActions->addWidget(nextStep_);
    statusLayout->addLayout(statusActions);
    layout->addWidget(statusHelpPanel_);
    statusHelpPanel_->hide();
    connect(fieldHelpToggle_, &QPushButton::toggled, this, [this](bool checked) {
        fieldHelpArea_->setVisible(checked);
        updateHelp();
        QTimer::singleShot(0, fields_, [this] {
            if (fields_->currentItem()) fields_->scrollToItem(fields_->currentItem());
        });
    });
    connect(state_, &QPushButton::toggled, this, [this](bool checked) {
        statusHelpPanel_->setVisible(checked);
        updateHelp();
    });
    connect(nextStep_, &QPushButton::clicked, this, [this] {
        if (status_ == AnalysisStatus::Complete || status_ == AnalysisStatus::Unsupported ||
            status_ == AnalysisStatus::AuthenticationFailed) bytes_->setFocus();
        else emit analysisHelpRequested(status_);
    });
    connect(packets_, &QComboBox::currentIndexChanged, this, [this] {
        locate_->setEnabled(navigationEnabled_ && packets_->currentIndex() >= 0);
    });
    connect(previous, &QPushButton::clicked, this,
            [this] { page(offset_ >= 4096 ? offset_ - 4096 : 0); });
    connect(next, &QPushButton::clicked, this, [this] { page(offset_ + 4096); });
    connect(list_, &QTreeWidget::currentItemChanged, this, [this] { select(); });
    connect(sources_, &QComboBox::currentIndexChanged, this, [this] { rebuild(); });
    connect(locate, &QPushButton::clicked, this, [this] {
        if (navigationEnabled_ && packets_->currentIndex() >= 0)
            emit locateRequested(packets_->currentData().toULongLong());
    });
    connect(fields_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem *item) {
        updateHelp();
        fieldKey_ = item ? item->data(0, Qt::UserRole + 7).toString() : QString{};
        if (!item || !selected_ || !fieldByKey_.contains(fieldKey_)) return;
        page(fieldByKey_.value(fieldKey_)->offset / 4096 * 4096);
    });
    connect(&fillTimer_, &QTimer::timeout, this, &ApplicationView::fill);
    fillTimer_.setInterval(0);
    fields_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(fields_, &QTreeWidget::customContextMenuRequested, this, [this](QPoint position) {
        auto *item = position.x() < 0 ? fields_->currentItem() : fields_->itemAt(position);
        if (!item || !selected_) return;
        fields_->setCurrentItem(item);
        const auto targetKey = item->data(0, Qt::UserRole + 7).toString();
        const auto *field = fieldByKey_.value(targetKey);
        if (!field) return;
        const auto value = QString::fromStdString(applicationText(field->value));
        const auto name = i18n::text(QString::fromStdString(field->name));
        const auto predicate = learning::fieldPredicate(QString::fromStdString(field->key), field->value);
        const auto offset = field->offset, length = field->length;
        const auto bytes = selected_->bytes;
        const auto context = context_;
        const auto epoch = bindingEpoch_;
        const auto messageKey = selectedKey_;
        const auto fieldKey = item->data(0, Qt::UserRole + 7).toString();
        auto *menu = new QMenu(fields_);
        menu->setObjectName("applicationFieldMenu");
        auto add = [&](const char *caption, const char *id, auto callback, bool enabled = true) {
            auto *action = menu->addAction(i18n::text(caption));
            action->setObjectName(id);
            action->setEnabled(enabled);
            connect(action, &QAction::triggered, menu, [this, context, epoch, messageKey, fieldKey, callback] {
                if (context_ == context && navigationEnabled_ && menuTargetValid(epoch, messageKey, fieldKey)) callback();
                else QToolTip::showText(QCursor::pos(), i18n::text("操作目标已失效，请重新选择报文"), fields_);
            });
        };
        add("复制值", "copyApplicationField", [value] { qApp->clipboard()->setText(value); });
        add("复制字段和值", "copyApplicationFieldPair", [name, value] { qApp->clipboard()->setText(name + '\t' + value); });
        add("复制对应字节", "copyApplicationFieldBytes", [bytes, offset, length] {
            qApp->clipboard()->setText(QString::fromLatin1(QByteArray(
                reinterpret_cast<const char *>(bytes->data() + offset), qsizetype(length)).toHex(' ')));
        }, bytes && length && offset <= bytes->size() && length <= bytes->size() - offset);
        for (bool unique : {true, false})
            add(unique ? "作为唯一筛选" : "加入当前筛选", unique ? "applicationFilterOnly" : "applicationFilterAdd",
                [this, predicate, unique, context] { emit filterRequested(predicate, unique, context); }, !predicate.isEmpty());
        connect(menu, &QMenu::aboutToHide, menu, &QObject::deleteLater);
        menu->popup(fields_->viewport()->mapToGlobal(position.x() < 0 ? fields_->visualItemRect(item).center() : position));
    });
    auto *copyField = new QShortcut(QKeySequence::Copy, fields_);
    copyField->setContext(Qt::WidgetWithChildrenShortcut);
    connect(copyField, &QShortcut::activated, this, [this] {
        if (auto *item = fields_->currentItem()) qApp->clipboard()->setText(item->text(1));
    });
    for (auto sequence : {QKeySequence(Qt::SHIFT | Qt::Key_F10), QKeySequence(Qt::Key_Menu)}) {
        auto *shortcut = new QShortcut(sequence, fields_);
        shortcut->setContext(Qt::WidgetWithChildrenShortcut);
        connect(shortcut, &QShortcut::activated, this, [this] { emit fields_->customContextMenuRequested(QPoint(-1, -1)); });
    }
    i18n::bind(this);
    connect(&i18n::language(), &i18n::Language::changed, this, [this] {
        rebuild();
    });
    rebuild();
    state_->setText(statusText(status_));
    updateHelp();
}
ApplicationView::~ApplicationView() {
    // Child widgets outlive members and may emit selection signals while closing.
    fillTimer_.stop();
    disconnect(list_, nullptr, this, nullptr);
    disconnect(fields_, nullptr, this, nullptr);
    disconnect(sources_, nullptr, this, nullptr);
}
void ApplicationView::setNavigationEnabled(bool enabled) {
    navigationEnabled_ = enabled;
    locate_->setEnabled(enabled && packets_->currentIndex() >= 0);
    nextStep_->setEnabled(enabled);
}
void ApplicationView::resizeEvent(QResizeEvent *event) {
    QWidget::resizeEvent(event);
    lower_->setOrientation(width() < 760 ? Qt::Vertical : Qt::Horizontal);
}
void ApplicationView::updateHelp() {
    const auto *item = fields_->currentItem();
    updateExplanation(fieldHelp_, item ? learning::fieldExplanation(item->data(0, Qt::UserRole + 5).toString(), item->text(1))
                            : i18n::text("选择字段以查看说明"));
    updateExplanation(statusHelp_, learning::statusExplanation(status_));
    const bool complete = status_ == AnalysisStatus::Complete;
    const bool failed = status_ == AnalysisStatus::AuthenticationFailed;
    const bool pending = status_ == AnalysisStatus::Pending;
    const QString tone = complete ? "success" : failed ? "error" : pending ? "muted" : "warning";
    if (state_->property("statusTone").toString() != tone) {
        state_->setProperty("statusTone", tone);
        state_->style()->unpolish(state_);
        state_->style()->polish(state_);
        icons::bind(state_, complete ? icons::Id::Check : failed ? icons::Id::Error : pending ? icons::Id::Info : icons::Id::Warning);
    }
    nextStep_->setText(i18n::text(status_ == AnalysisStatus::MissingKeys ? "TLS key log"
                                   : (status_ == AnalysisStatus::Pending || status_ == AnalysisStatus::Limited ||
                                      status_ == AnalysisStatus::Incomplete ? "调整筛选" : "查看字节")));
}
namespace {
QString messageBase(const ApplicationMessage &m) {
    QString key = QString::fromStdString(m.protocol) + '/' + QString::number(int(m.source)) + '/' +
                  QString::number(m.direction) + '/' + QString::number(m.streamId) + '/';
    if (m.streamOffset) return key + "s" + QString::number(*m.streamOffset);
    key += "p";
    if (!m.sources.empty()) key += QString::number(m.sources.front().packetId) + ':' + QString::number(m.sources.front().rawOffset);
    return key + ':' + QString::number(m.offset);
}
QString fieldBase(const ApplicationField &field) {
    return QString::fromStdString(field.key.empty() ? "n:" + field.name : "k:" + field.key) + '/' + QString::number(field.offset);
}
struct TreeAnchor {
    QString key;
    int offset{}, vertical{}, horizontal{};
    explicit TreeAnchor(QTreeWidget *tree) {
        vertical = tree->verticalScrollBar()->value();
        horizontal = tree->horizontalScrollBar()->value();
        if (auto *item = tree->itemAt(2, 2)) {
            key = item->data(0, Qt::UserRole + 7).toString();
            offset = tree->visualItemRect(item).top();
        }
    }
    void restore(QTreeWidget *tree, const QHash<QString, QTreeWidgetItem *> &items) const {
        if (auto *item = items.value(key)) {
            tree->scrollToItem(item, QAbstractItemView::PositionAtTop);
            tree->verticalScrollBar()->setValue(tree->verticalScrollBar()->value() - offset);
        } else tree->verticalScrollBar()->setValue(vertical);
        tree->horizontalScrollBar()->setValue(horizontal);
    }
};
void moveRow(QTreeWidget *tree, QTreeWidgetItem *item, int position) {
    const auto old = tree->indexOfTopLevelItem(item);
    if (old == position) return;
    if (old >= 0) tree->takeTopLevelItem(old);
    tree->insertTopLevelItem(position, item);
}
}
void ApplicationView::setSourceContext(SourceContext context) {
    setBinding(context, scope_, scopeId_);
}
void ApplicationView::setBinding(SourceContext context, Scope scope, std::uint64_t id, bool reset) {
    if (!reset && context_ == context && scope_ == scope && scopeId_ == id) return;
    context_ = context; scope_ = scope; scopeId_ = id;
    ++bindingEpoch_;
    resetPresentation();
}
void ApplicationView::resetPresentation() {
    fillTimer_.stop();
    updating_ = false; pendingResults_.reset();
    selected_ = nullptr; selectedKey_.clear(); fieldKey_.clear();
    messageByKey_.clear(); messageCounts_.clear(); fieldByKey_.clear();
    messages_.clear(); fieldRows_.clear(); removals_.clear();
    messageItems_.clear(); fieldItems_.clear();
    {
        const QSignalBlocker block(list_);
        list_->clear();
    }
    results_.clear();
    firstSelection_ = true; lostSelection_ = false;
    selectionHint_->hide();
    fieldHelpToggle_->setChecked(false); state_->setChecked(false);
    clearDetails();
    status_ = AnalysisStatus::Pending;
    state_->setText(statusText(status_));
    updateHelp();
}
void ApplicationView::setResults(Results results) {
    if (pendingResults_ && *pendingResults_ == results) return;
    if (!pendingResults_ && results_ == results) return;
    pendingResults_ = std::move(results);
    fillTimer_.start();
    if (!updating_) fill();
}
void ApplicationView::rebuild() {
    if (!pendingResults_) pendingResults_ = results_;
    if (!updating_) fillTimer_.start();
}
void ApplicationView::beginUpdate() {
    if (!pendingResults_) return;
    // All visible rows resolve through keys, never through old result pointers.
    const bool ambiguous = selected_ && messageCounts_.value(messageBase(*selected_)) > 1;
    selected_ = nullptr;
    results_ = std::move(*pendingResults_); pendingResults_.reset();
    messages_.clear(); messageByKey_.clear(); messageCounts_.clear();
    for (const auto &result : results_)
        for (const auto &message : result->messages) {
            if (sources_->currentIndex() && sources_->currentIndex() != int(message.source) + 1) continue;
            const auto base = messageBase(message);
            const auto occurrence = messageCounts_[base]++;
            const auto key = base + '/' + QString::number(occurrence);
            messages_.push_back({key, base, &message});
            messageByKey_.insert(key, &message);
        }
    const auto *candidate = messageByKey_.value(selectedKey_);
    if (!ambiguous && candidate && messageCounts_.value(messageBase(*candidate)) == 1) selected_ = candidate;
    else if (!selectedKey_.isEmpty()) {
        selectedKey_.clear(); fieldKey_.clear(); lostSelection_ = true; firstSelection_ = false;
        clearDetails();
    }
    removals_.clear();
    for (auto it = messageItems_.cbegin(); it != messageItems_.cend(); ++it)
        if (!messageByKey_.contains(it.key())) removals_.append(it.key());
    rowCursor_ = removeCursor_ = 0;
    messagesDone_ = false; updating_ = true;
    auto status = AnalysisStatus::Complete;
    QString error;
    for (const auto &result : results_) {
        if (result->status != AnalysisStatus::Complete) status = result->status;
        if (!result->error.empty()) error = i18n::text(QString::fromStdString(result->error));
    }
    status_ = results_.empty() ? AnalysisStatus::Pending : status;
    state_->setText(statusText(status_));
    state_->setToolTip(error.isEmpty() ? i18n::text("查看状态说明") : error);
    i18n::setLabel(selectionHint_, lostSelection_ ? "当前结果中已无所选消息，请重新选择" : "");
    selectionHint_->setVisible(lostSelection_);
    prepareFields();
}
void ApplicationView::prepareFields() {
    fieldRows_.clear(); fieldByKey_.clear();
    if (selected_) {
        QHash<QString, int> occurrences;
        for (const auto &field : selected_->fields) {
            const auto base = fieldBase(field);
            const auto key = base + '/' + QString::number(occurrences[base]++);
            fieldRows_.push_back({key, &field});
            fieldByKey_.insert(key, &field);
        }
    }
    if (!fieldByKey_.contains(fieldKey_)) fieldKey_.clear();
    fieldDirty_ = true;
}
void ApplicationView::fill() {
    QElapsedTimer clock; clock.start();
    if (!updating_ && pendingResults_) beginUpdate();
    if (!updating_) { fillTimer_.stop(); return; }
    const TreeAnchor listAnchor(list_), fieldAnchor(fields_);
    const QSignalBlocker listBlock(list_), fieldBlock(fields_);
    while (!messagesDone_ && clock.nsecsElapsed() < 2000000) {
        if (removeCursor_ < std::size_t(removals_.size())) {
            delete messageItems_.take(removals_[qsizetype(removeCursor_++)]);
        } else if (rowCursor_ < messages_.size()) {
            const auto &row = messages_[rowCursor_];
            auto *item = messageItems_.value(row.key);
            if (!item) { item = new QTreeWidgetItem; messageItems_.insert(row.key, item); }
            moveRow(list_, item, int(rowCursor_));
            const auto &m = *row.message;
            item->setText(0, QString::fromStdString(m.protocol));
            item->setText(1, m.direction ? "B -> A" : "A -> B");
            item->setText(2, QString::fromStdString(m.summary)); item->setToolTip(2, item->text(2));
            item->setText(3, m.status == AnalysisStatus::Complete ? QString{} : i18n::text("Incomplete"));
            item->setData(0, Qt::UserRole + 7, row.key);
            item->setData(0, Qt::UserRole + 8, qulonglong(m.bytes ? m.bytes->size() : 0));
            ++rowCursor_;
        } else {
            messagesDone_ = true;
            if (firstSelection_ && !messages_.empty()) {
                firstSelection_ = false; freshSelection_ = true;
                selectedKey_ = messages_.front().key;
                selected_ = messages_.front().message;
                prepareFields();
                offset_ = selected_->offset / 4096 * 4096;
            }
            removals_.clear(); removeCursor_ = rowCursor_ = 0;
            for (auto it = fieldItems_.cbegin(); it != fieldItems_.cend(); ++it)
                if (!fieldByKey_.contains(it.key())) removals_.append(it.key());
        }
    }
    if (messagesDone_ && fieldDirty_) {
        while (clock.nsecsElapsed() < 2000000) {
            if (removeCursor_ < std::size_t(removals_.size())) {
                delete fieldItems_.take(removals_[qsizetype(removeCursor_++)]);
            } else if (rowCursor_ < fieldRows_.size()) {
                const auto &row = fieldRows_[rowCursor_]; const auto &f = *row.field;
                auto *item = fieldItems_.value(row.key);
                if (!item) { item = new QTreeWidgetItem; fieldItems_.insert(row.key, item); }
                moveRow(fields_, item, int(rowCursor_));
                item->setText(0, i18n::text(QString::fromStdString(f.name)));
                item->setText(1, QString::fromStdString(applicationText(f.value))); item->setToolTip(1, item->text(1));
                item->setData(0, Qt::UserRole, qulonglong(f.offset));
                item->setData(1, Qt::UserRole, qulonglong(f.length));
                item->setData(0, Qt::UserRole + 5, QString::fromStdString(f.key));
                item->setData(0, Qt::UserRole + 6, learning::fieldPredicate(QString::fromStdString(f.key), f.value));
                item->setData(0, Qt::UserRole + 7, row.key);
                ++rowCursor_;
            } else {
                fieldDirty_ = false; updating_ = false;
                finishFields(); break;
            }
        }
    }
    list_->setCurrentItem(messageItems_.value(selectedKey_));
    fields_->setCurrentItem(fieldItems_.value(fieldKey_));
    listAnchor.restore(list_, messageItems_); fieldAnchor.restore(fields_, fieldItems_);
    if (!updating_ && !pendingResults_) fillTimer_.stop();
}
void ApplicationView::finishFields() {
    const QSignalBlocker block(fields_);
    fields_->setCurrentItem(fieldItems_.value(fieldKey_));
    page(offset_, !freshSelection_);
    freshSelection_ = false;
    updateHelp();
}
void ApplicationView::clearDetails() {
    const QSignalBlocker fieldBlock(fields_), packetBlock(packets_);
    fieldItems_.clear(); fieldByKey_.clear(); fieldRows_.clear();
    fields_->clear(); packets_->clear(); bytes_->clear(); offset_ = 0;
    pager_->hide(); page_->clear(); locate_->setEnabled(false);
    previous_->setEnabled(false); next_->setEnabled(false);
    updateHelp();
}
void ApplicationView::select() {
    auto *item = list_->currentItem();
    selectedKey_ = item ? item->data(0, Qt::UserRole + 7).toString() : QString{};
    selected_ = messageByKey_.value(selectedKey_);
    if (!selected_) { selectedKey_.clear(); clearDetails(); return; }
    firstSelection_ = false; lostSelection_ = false; selectionHint_->hide();
    fieldKey_.clear();
    clearDetails();
    offset_ = selected_->offset / 4096 * 4096;
    prepareFields();
    // A user selection supersedes any old field work, including a pending snapshot slice.
    if (messagesDone_) {
        removals_.clear(); rowCursor_ = removeCursor_ = 0;
        updating_ = true;
    }
    page(offset_);
    fillTimer_.start();
}
void ApplicationView::syncPackets(bool preserve) {
    const auto old = packets_->currentData();
    std::vector<qulonglong> ids;
    if (selected_) for (const auto &span : selected_->sources) {
        const auto *field = fieldByKey_.value(fieldKey_);
        const auto length = span.bufferLength ? span.bufferLength : span.length;
        if (field && field->length && !(span.bufferOffset < field->offset + field->length && span.bufferOffset + length > field->offset)) continue;
        if (std::find(ids.begin(), ids.end(), span.packetId) == ids.end()) ids.push_back(span.packetId);
    }
    bool equal = packets_->count() == int(ids.size());
    for (int i = 0; equal && i < packets_->count(); ++i) equal = packets_->itemData(i).toULongLong() == ids[std::size_t(i)];
    if (!equal) {
        const QSignalBlocker block(packets_);
        packets_->clear();
        for (auto id : ids) packets_->addItem(QString::number(id), QVariant::fromValue(id));
        if (preserve) packets_->setCurrentIndex(old.isValid() ? packets_->findData(old) : -1);
    }
    locate_->setEnabled(navigationEnabled_ && packets_->currentIndex() >= 0);
}
bool ApplicationView::menuTargetValid(quint64 epoch, const QString &message, const QString &field) const {
    const auto *m = messageByKey_.value(message);
    return epoch == bindingEpoch_ && message == selectedKey_ && m &&
           messageCounts_.value(messageBase(*m)) == 1 && fieldByKey_.contains(field);
}
void ApplicationView::page(std::size_t offset, bool preserve) {
    if (!selected_ || !selected_->bytes) {
        bytes_->clear(); page_->clear(); pager_->hide();
        previous_->setEnabled(false); next_->setEnabled(false); syncPackets(preserve); return;
    }
    const auto vertical = bytes_->verticalScrollBar()->value(), horizontal = bytes_->horizontalScrollBar()->value();
    const auto &content = *selected_->bytes;
    offset_ = content.empty() ? 0 : std::min(offset / 4096, (content.size() - 1) / 4096) * 4096;
    const auto end = std::min(content.size(), offset_ + 4096);
    QString text;
    for (auto at = offset_; at < end; at += 16) {
        text += QString("%1  ").arg(qulonglong(at), 6, 16, QChar('0'));
        for (unsigned j = 0; j < 16; ++j)
            text += at + j < end ? QString("%1 ").arg(content[at + j], 2, 16, QChar('0')) : "   ";
        text += "  ";
        for (unsigned j = 0; j < 16 && at + j < end; ++j) {
            const auto c = content[at + j]; text += c >= 32 && c < 127 ? QChar(c) : QChar('.');
        }
        text += '\n';
    }
    if (bytes_->toPlainText() != text) bytes_->setPlainText(text);
    if (preserve) {
        bytes_->verticalScrollBar()->setValue(vertical); bytes_->horizontalScrollBar()->setValue(horizontal);
    }
    const auto pages = (content.size() + 4095) / 4096;
    pager_->setVisible(pages > 1); previous_->setEnabled(offset_ > 0); next_->setEnabled(end < content.size());
    page_->setText(i18n::text("第 %1/%2 页，字节 %3-%4 / %5")
                       .arg(qulonglong(offset_ / 4096 + 1)).arg(qulonglong(pages))
                       .arg(qulonglong(offset_)).arg(qulonglong(end ? end - 1 : 0)).arg(qulonglong(content.size())));
    highlightField(); syncPackets(preserve);
}
void ApplicationView::highlightField() {
    QList<QTextEdit::ExtraSelection> selections;
    auto *item = fields_->currentItem();
    if (!selected_ || !selected_->bytes || !item) {
        bytes_->setExtraSelections(selections);
        return;
    }
    const auto first = static_cast<std::size_t>(item->data(0, Qt::UserRole).toULongLong());
    const auto length = static_cast<std::size_t>(item->data(1, Qt::UserRole).toULongLong());
    const auto size = selected_->bytes->size();
    if (first > size || length > size - first)
        return;
    const auto last = first + length;
    // Source spans refer to the selected data source, including authenticated plaintext.
    const auto end = std::min({last, size, offset_ + 4096});
    for (auto at = std::max(first, offset_); at < end;) {
        const auto row = (at - offset_) / 16, column = (at - offset_) % 16;
        const auto count = std::min<std::size_t>(16 - column, end - at);
        const auto block = bytes_->document()->findBlockByNumber(static_cast<int>(row));
        if (!block.isValid())
            break;
        const auto mark = [&](int start, int count) {
            QTextEdit::ExtraSelection selection;
            selection.cursor = QTextCursor(bytes_->document());
            selection.cursor.setPosition(block.position() + start);
            selection.cursor.setPosition(block.position() + start + count, QTextCursor::KeepAnchor);
            selection.format.setBackground(palette().highlight());
            selection.format.setForeground(palette().highlightedText());
            selections.push_back(std::move(selection));
        };
        mark(8 + static_cast<int>(3 * column), static_cast<int>(3 * count - 1));
        mark(58 + static_cast<int>(column), static_cast<int>(count));
        at += count;
    }
    bytes_->setExtraSelections(selections);
}
} // namespace etherscope
