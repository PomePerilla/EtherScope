#include "ui/find_bar.h"
#include "ui/language.h"
#include "ui/flow_layout.h"
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QElapsedTimer>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QShortcut>
#include <QSignalBlocker>
#include <QPlainTextEdit>
#include <QTextBlock>
#include <QKeyEvent>
#include <algorithm>
namespace etherscope {
void highlightFindBytes(QPlainTextEdit *view, std::size_t page, std::size_t size,
                        std::size_t offset, std::size_t length) {
    QList<QTextEdit::ExtraSelection> marks;
    const auto end = offset <= size
                         ? std::min({size, offset + std::min(length, size - offset), page + 4096})
                         : 0;
    for (auto at = std::max(offset, page); at < end;) {
        const auto count = std::min<std::size_t>(16 - at % 16, end - at);
        const auto block = view->document()->findBlockByNumber(int((at - page) / 16));
        if (!block.isValid())
            break;
        QTextEdit::ExtraSelection mark;
        mark.cursor = QTextCursor(view->document());
        mark.cursor.setPosition(block.position() + 8 + int(at % 16) * 3);
        mark.cursor.setPosition(mark.cursor.position() + int(count * 3 - 1),
                                QTextCursor::KeepAnchor);
        mark.format.setBackground(view->palette().highlight());
        mark.format.setForeground(view->palette().highlightedText());
        marks.append(mark);
        at += count;
    }
    view->setExtraSelections(marks);
}
FindBar::FindBar(QWidget *parent) : QWidget(parent) {
    setObjectName("findBar");
    auto *layout = new FlowLayout(this, 4);
    scope_ = new QComboBox(this);
    scope_->setObjectName("findScope");
    input_ = new QLineEdit(this);
    input_->setObjectName("findInput");
    input_->setMaxLength(4096);
    input_->setPlaceholderText("查找内容，按 Enter 开始");
    input_->setMinimumWidth(180);
    mode_ = new QComboBox(this);
    mode_->setObjectName("findMode");
    mode_->addItems({"文本", "十六进制"});
    case_ = new QCheckBox("区分大小写", this);
    case_->setObjectName("findCase");
    auto button = [&](const char *text, const char *name) {
        auto *b = new QPushButton(text, this);
        b->setObjectName(name);
        layout->addWidget(b);
        return b;
    };
    layout->addWidget(scope_);
    layout->addWidget(input_);
    layout->addWidget(mode_);
    layout->addWidget(case_);
    previous_ = button("上一个", "findPrevious");
    next_ = button("下一个", "findNext");
    auto *refresh = button("重新查找", "findRefresh");
    status_ = new QLabel(this);
    status_->setObjectName("findStatus");
    layout->addWidget(status_);
    auto *close = button("关闭查找", "findClose");
    connect(input_, &QLineEdit::returnPressed, this, &FindBar::start);
    connect(input_, &QLineEdit::textEdited, this, &FindBar::invalidate);
    connect(case_, &QCheckBox::toggled, this, &FindBar::invalidate);
    connect(mode_, &QComboBox::currentIndexChanged, this, &FindBar::invalidate);
    connect(refresh, &QPushButton::clicked, this, &FindBar::start);
    connect(previous_, &QPushButton::clicked, this, [this] { move(-1); });
    connect(next_, &QPushButton::clicked, this, [this] { move(1); });
    connect(close, &QPushButton::clicked, this, [this] {
        invalidate();
        hide();
    });
    connect(scope_, &QComboBox::currentIndexChanged, this, [this] {
        invalidate();
        mode_->setEnabled(targets_[std::size_t(scope_->currentIndex())].bytes);
        if (!mode_->isEnabled())
            mode_->setCurrentIndex(0);
    });
    auto *escape = new QShortcut(QKeySequence(Qt::Key_Escape), this);
    escape->setContext(Qt::WidgetWithChildrenShortcut);
    connect(escape, &QShortcut::activated, close, &QPushButton::click);
    timer_.setInterval(0);
    connect(&timer_, &QTimer::timeout, this, &FindBar::scan);
    for (auto key : {QKeySequence::FindNext, QKeySequence::FindPrevious}) {
        auto *shortcut = new QShortcut(key, this);
        shortcut->setContext(Qt::WidgetWithChildrenShortcut);
        connect(shortcut, &QShortcut::activated, this,
                [this, key] { move(key == QKeySequence::FindNext ? 1 : -1); });
    }
    hide();
    updateStatus();
    for (auto *widget : findChildren<QWidget *>(QString(), Qt::FindDirectChildrenOnly))
        widget->installEventFilter(this);
}
bool FindBar::eventFilter(QObject *watched, QEvent *event) {
    if ((event->type() == QEvent::ShortcutOverride || event->type() == QEvent::KeyPress) &&
        static_cast<QKeyEvent *>(event)->key() == Qt::Key_Escape &&
        !QApplication::activePopupWidget()) {
        event->accept();
        if (event->type() == QEvent::KeyPress) {
            invalidate();
            hide();
            if (scope_->currentIndex() >= 0)
                targets_[std::size_t(scope_->currentIndex())].focus->setFocus();
        }
        return true;
    }
    return QWidget::eventFilter(watched, event);
}
void FindBar::addTarget(FindTarget target) {
    const QSignalBlocker block(scope_);
    scope_->addItem(target.name);
    targets_.push_back(std::move(target));
    mode_->setEnabled(targets_.front().bytes);
}
void FindBar::openFor(QWidget *focus) {
    for (int i = 0; i < int(targets_.size()); ++i)
        if (focus && (focus == targets_[std::size_t(i)].focus ||
                      targets_[std::size_t(i)].focus->isAncestorOf(focus))) {
            scope_->setCurrentIndex(i);
            break;
        }
    show();
    input_->setFocus();
    input_->selectAll();
}
void FindBar::invalidate() {
    timer_.stop();
    source_ = {};
    document_ = {};
    matches_.clear();
    current_ = -1;
    stale_ = limited_ = false;
    updateStatus();
}
void FindBar::markChanged() {
    if (!isHidden() && source_.read) {
        stale_ = true;
        updateStatus();
    }
}
void FindBar::message(const QString &text) {
    status_->setText(i18n::text(text));
    status_->setToolTip(status_->text());
}
void FindBar::start() {
    invalidate();
    if (scope_->currentIndex() < 0 || input_->text().isEmpty())
        return;
    query_ = input_->text();
    if (mode_->currentIndex() == 1) {
        auto hex = query_;
        hex.remove(' ');
        hex.remove('\t');
        hex.remove('\n');
        hex.remove('\r');
        bool valid = !hex.isEmpty() && hex.size() % 2 == 0;
        for (const auto c : hex)
            valid &= (c >= '0' && c <= '9') || (c.toLower() >= 'a' && c.toLower() <= 'f');
        if (!valid) {
            message("请输入完整的十六进制字节，例如 08 00");
            return;
        }
        needle_ = QByteArray::fromHex(hex.toLatin1());
    } else
        needle_ = query_.toUtf8();
    source_ = targets_[std::size_t(scope_->currentIndex())].capture();
    if (!source_.count) {
        source_ = {};
        updateStatus();
        return;
    }
    row_ = 0;
    byte_ = 0;
    documentReady_ = false;
    timer_.start();
    updateStatus();
}
void FindBar::scan() {
    if (!source_.valid || !source_.valid()) {
        invalidate();
        message("来源或内容已改变，请重新查找");
        return;
    }
    QElapsedTimer time;
    time.start();
    while (row_ < source_.count && time.nsecsElapsed() < 2000000 && matches_.size() < 10000) {
        if (!documentReady_) {
            document_ = source_.read(row_);
            documentReady_ = true;
            byte_ = 0;
        }
        if (!document_.bytes) {
            if (document_.text.contains(query_, case_->isChecked() ? Qt::CaseSensitive
                                                                   : Qt::CaseInsensitive))
                matches_.push_back({document_.key, 0, 0});
            ++row_;
            documentReady_ = false;
        } else {
            const auto &bytes = *document_.bytes;
            const auto fold = [](unsigned char c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; };
            const bool insensitive = mode_->currentIndex() == 0 && !case_->isChecked();
            for (int step = 0; step < 256 && byte_ <= bytes.size() &&
                               std::size_t(needle_.size()) <= bytes.size() - byte_;
                 ++step, ++byte_) {
                bool equal = true;
                for (qsizetype n = 0; n < needle_.size(); ++n) {
                    const auto a = bytes[byte_ + std::size_t(n)],
                               b = static_cast<unsigned char>(needle_[n]);
                    if (insensitive ? fold(a) != fold(b) : a != b) {
                        equal = false;
                        break;
                    }
                }
                if (equal)
                    matches_.push_back({document_.key, byte_, std::size_t(needle_.size())});
                if (matches_.size() == 10000) {
                    ++byte_;
                    break;
                }
            }
            if (byte_ > bytes.size() || std::size_t(needle_.size()) > bytes.size() - byte_) {
                ++row_;
                documentReady_ = false;
            }
        }
    }
    if (row_ == source_.count || matches_.size() == 10000) {
        limited_ = matches_.size() == 10000;
        timer_.stop();
        document_ = {};
        // Locating is explicit, so a background search never steals the reading position.
    }
    updateStatus();
}
void FindBar::move(int direction) {
    if (matches_.empty())
        return;
    if (!source_.valid || !source_.valid()) {
        invalidate();
        message("来源或内容已改变，请重新查找");
        return;
    }
    current_ = current_ < 0 ? (direction > 0 ? 0 : int(matches_.size()) - 1)
                            : (current_ + direction + int(matches_.size())) % int(matches_.size());
    const auto match = matches_[std::size_t(current_)];
    if (!targets_[std::size_t(scope_->currentIndex())].locate(match.key, match.offset,
                                                              match.length))
        message("目标已移出当前结果，请重新查找");
    else
        updateStatus();
}
void FindBar::updateStatus() {
    previous_->setEnabled(!matches_.empty());
    next_->setEnabled(!matches_.empty());
    QString text = timer_.isActive()
                       ? i18n::text("正在查找，已找到 %1 项").arg(matches_.size())
                       : i18n::text("%1 / %2 项").arg(current_ + 1).arg(matches_.size());
    if (limited_)
        text += " · " + i18n::text("已显示前 10000 项");
    if (stale_)
        text += " · " + i18n::text("内容已更新，可重新查找");
    status_->setText(text);
    status_->setToolTip(text);
}
} // namespace etherscope
