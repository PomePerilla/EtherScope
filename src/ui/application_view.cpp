#include "ui/application_view.h"
#include "ui/language.h"
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
    auto *bar = new QHBoxLayout;
    sources_ = new QComboBox(this);
    sources_->setObjectName("applicationDataSource");
    sources_->addItems({"All sources", "Original", "Reassembled", "Decrypted"});
    bar->addWidget(sources_);
    packets_ = new QComboBox(this);
    packets_->setObjectName("applicationPackets");
    bar->addWidget(packets_, 1);
    state_ = new QLabel(this);
    state_->setObjectName("applicationState");
    bar->addWidget(state_);
    auto *locate = new QPushButton("定位", this);
    bar->addWidget(locate);
    layout->addLayout(bar);
    auto *splitter = new QSplitter(Qt::Vertical, this);
    list_ = new QTreeWidget(splitter);
    list_->setObjectName("applicationMessages");
    list_->setHeaderLabels({"协议", "方向", "摘要", "状态"});
    list_->setUniformRowHeights(true);
    list_->setColumnWidth(0, 75);
    list_->setColumnWidth(1, 90);
    list_->setColumnWidth(2, 350);
    auto *lower = new QSplitter(Qt::Horizontal, splitter);
    fields_ = new QTreeWidget(lower);
    fields_->setObjectName("applicationFields");
    fields_->setHeaderLabels({"字段", "值"});
    fields_->setUniformRowHeights(true);
    fields_->setColumnWidth(0, 180);
    bytes_ = new QPlainTextEdit(lower);
    bytes_->setObjectName("applicationBytes");
    bytes_->setReadOnly(true);
    bytes_->setLineWrapMode(QPlainTextEdit::NoWrap);
    bytes_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    layout->addWidget(splitter, 1);
    auto *pager = new QHBoxLayout;
    auto *previous = new QPushButton("上一页", this);
    auto *next = new QPushButton("下一页", this);
    page_ = new QLabel(this);
    pager->addWidget(previous);
    pager->addWidget(page_, 1);
    pager->addWidget(next);
    layout->addLayout(pager);
    connect(previous, &QPushButton::clicked, this,
            [this] { page(offset_ >= 4096 ? offset_ - 4096 : 0); });
    connect(next, &QPushButton::clicked, this, [this] { page(offset_ + 4096); });
    connect(list_, &QTreeWidget::currentItemChanged, this, [this] { select(); });
    connect(sources_, &QComboBox::currentIndexChanged, this, [this] { rebuild(); });
    connect(locate, &QPushButton::clicked, this, [this] {
        if (packets_->currentIndex() >= 0)
            emit locateRequested(packets_->currentData().toULongLong());
    });
    connect(fields_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem *item) {
        if (!item || !selected_)
            return;
        const auto offset = item->data(0, Qt::UserRole).toULongLong();
        page(static_cast<std::size_t>(offset / 4096 * 4096));
    });
    connect(&fillTimer_, &QTimer::timeout, this, &ApplicationView::fill);
    fillTimer_.setInterval(0);
    i18n::bind(this);
    connect(&i18n::language(), &i18n::Language::changed, this, &ApplicationView::rebuild);
    rebuild();
}
ApplicationView::~ApplicationView() {
    // Child widgets outlive members and may emit selection signals while closing.
    fillTimer_.stop();
    disconnect(list_, nullptr, this, nullptr);
    disconnect(fields_, nullptr, this, nullptr);
    disconnect(sources_, nullptr, this, nullptr);
}
void ApplicationView::setResults(std::vector<std::shared_ptr<const ApplicationResult>> results) {
    // Shared result identity is stable until the connection revision changes.
    if (results_ == results)
        return;
    const auto previous = selected_ ? std::optional<ApplicationMessage>(*selected_) : std::nullopt;
    results_ = std::move(results);
    selected_ = nullptr;
    rebuild();
    if (previous)
        for (std::size_t i = 0; i < messages_.size(); ++i) {
            const auto &message = *messages_[i];
            if (message.protocol == previous->protocol &&
                message.direction == previous->direction && message.offset == previous->offset &&
                message.streamId == previous->streamId) {
                preferredMessage_ = i;
                break;
            }
        }
}
void ApplicationView::rebuild() {
    preferredMessage_ =
        list_->currentItem() ? list_->currentItem()->data(0, Qt::UserRole).toULongLong() : 0;
    fillTimer_.stop();
    selected_ = nullptr;
    messages_.clear();
    list_->clear();
    fields_->clear();
    bytes_->clear();
    packets_->clear();
    filled_ = fieldFilled_ = 0;
    for (const auto &r : results_)
        for (const auto &message : r->messages)
            if (!sources_->currentIndex() || sources_->currentIndex() == int(message.source) + 1)
                messages_.push_back(&message);
    auto status = AnalysisStatus::Complete;
    QString error;
    for (const auto &result : results_) {
        if (result->status != AnalysisStatus::Complete)
            status = result->status;
        if (!result->error.empty())
            error = i18n::text(QString::fromStdString(result->error));
    }
    state_->setText(results_.empty() ? i18n::text("Pending analysis") : statusText(status));
    state_->setToolTip(error);
    if (preferredMessage_ >= messages_.size())
        preferredMessage_ = 0;
    fillTimer_.start();
}
void ApplicationView::fill() {
    QElapsedTimer elapsed;
    elapsed.start();
    while (filled_ < messages_.size() && elapsed.nsecsElapsed() < 2000000) {
        const auto *m = messages_[filled_];
        auto *item = new QTreeWidgetItem(list_);
        item->setText(0, QString::fromStdString(m->protocol));
        item->setText(1, m->direction ? "B -> A" : "A -> B");
        item->setText(2, QString::fromStdString(m->summary));
        item->setToolTip(2, item->text(2));
        item->setText(3,
                      m->status == AnalysisStatus::Complete ? QString{} : i18n::text("Incomplete"));
        item->setData(0, Qt::UserRole, qulonglong(filled_++));
    }
    while (selected_ && fieldFilled_ < selected_->fields.size() &&
           elapsed.nsecsElapsed() < 2000000) {
        const auto &field = selected_->fields[fieldFilled_++];
        auto *item = new QTreeWidgetItem(fields_);
        item->setText(0, i18n::text(QString::fromStdString(field.name)));
        item->setText(1, QString::fromStdString(applicationText(field.value)));
        item->setToolTip(1, item->text(1));
        item->setData(0, Qt::UserRole, qulonglong(field.offset));
        item->setData(1, Qt::UserRole, qulonglong(field.length));
    }
    if (filled_ == messages_.size() && (!selected_ || fieldFilled_ == selected_->fields.size()))
        fillTimer_.stop();
    if (!selected_ && std::size_t(list_->topLevelItemCount()) > preferredMessage_)
        list_->setCurrentItem(list_->topLevelItem(static_cast<int>(preferredMessage_)));
}
void ApplicationView::select() {
    auto *item = list_->currentItem();
    selected_ = item && item->data(0, Qt::UserRole).toULongLong() < messages_.size()
                    ? messages_[item->data(0, Qt::UserRole).toULongLong()]
                    : nullptr;
    fields_->clear();
    packets_->clear();
    fieldFilled_ = 0;
    if (selected_)
        for (const auto &source : selected_->sources)
            if (packets_->findData(QVariant::fromValue<qulonglong>(source.packetId)) < 0)
                packets_->addItem(QString::number(source.packetId),
                                  QVariant::fromValue<qulonglong>(source.packetId));
    page(selected_ ? selected_->offset / 4096 * 4096 : 0);
    fillTimer_.start();
}
void ApplicationView::page(std::size_t offset) {
    if (!selected_ || !selected_->bytes) {
        bytes_->clear();
        page_->clear();
        return;
    }
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
            const auto c = content[at + j];
            text += c >= 32 && c < 127 ? QChar(c) : QChar('.');
        }
        text += '\n';
    }
    bytes_->setPlainText(text);
    page_->setText(QString("%1-%2 / %3")
                       .arg(qulonglong(offset_))
                       .arg(qulonglong(end ? end - 1 : 0))
                       .arg(qulonglong(content.size())));
    highlightField();
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
    if (length) {
        packets_->clear();
        for (const auto &source : selected_->sources) {
            const auto count = source.bufferLength ? source.bufferLength : source.length;
            if (source.bufferOffset < last && source.bufferOffset + count > first &&
                packets_->findData(QVariant::fromValue<qulonglong>(source.packetId)) < 0)
                packets_->addItem(QString::number(source.packetId),
                                  QVariant::fromValue<qulonglong>(source.packetId));
        }
    }
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
