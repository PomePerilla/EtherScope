#include "ui/window_title_bar.h"
#include "ui/icons.h"
#include "ui/language.h"
#include "ui/style.h"
#include <QAbstractButton>
#include <QContextMenuEvent>
#include <QEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QWindow>

namespace etherscope {
namespace {
enum class Caption { Minimize, Maximize, Close };
class CaptionButton final : public QAbstractButton {
  public:
    CaptionButton(Caption caption, QWidget *window, QWidget *parent)
        : QAbstractButton(parent), caption_(caption), window_(window) {
        setFixedSize(44, 32);
        setFocusPolicy(Qt::NoFocus);
        setProperty("_languageBound", true);
    }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const auto c = style::colors(palette().color(QPalette::Base).lightness() < 128);
        const bool hovered = underMouse() && isEnabled();
        const bool closeHover = hovered && caption_ == Caption::Close;
        if (hovered || isDown())
            painter.fillRect(rect(), closeHover ? QColor(isDown() ? "#A82318" : "#C42B1C")
                                                : QColor(isDown() ? c.selection : c.hover));
        painter.setPen(QPen(closeHover ? QColor("#FFFFFF") : QColor(c.text), 1.2, Qt::SolidLine,
                            Qt::SquareCap));
        const QPointF center(width() / 2., height() / 2.);
        switch (caption_) {
        case Caption::Minimize:
            painter.drawLine(center + QPointF(-5, 0), center + QPointF(5, 0));
            break;
        case Caption::Maximize:
            if (window_->isMaximized()) {
                painter.drawLine(center + QPointF(-3, -5), center + QPointF(5, -5));
                painter.drawLine(center + QPointF(5, -5), center + QPointF(5, 3));
                painter.drawRect(QRectF(center + QPointF(-5, -3), QSizeF(8, 8)));
            } else {
                painter.drawRect(QRectF(center + QPointF(-4.5, -4.5), QSizeF(9, 9)));
            }
            break;
        case Caption::Close:
            painter.drawLine(center + QPointF(-4.5, -4.5), center + QPointF(4.5, 4.5));
            painter.drawLine(center + QPointF(4.5, -4.5), center + QPointF(-4.5, 4.5));
            break;
        }
    }
    void enterEvent(QEnterEvent *event) override {
        QAbstractButton::enterEvent(event);
        update();
    }
    void leaveEvent(QEvent *event) override {
        QAbstractButton::leaveEvent(event);
        update();
    }

  private:
    Caption caption_;
    QWidget *window_;
};
} // namespace

WindowTitleBar::WindowTitleBar(QWidget *window, QWidget *parent)
    : QWidget(parent), window_(window) {
    setObjectName("windowTitleBar");
    setFixedHeight(32);
    setAttribute(Qt::WA_StyledBackground);
    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(12, 0, 0, 0);
    layout->setSpacing(8);
    auto *brand = new QLabel(this);
    brand->setObjectName("windowBrand");
    brand->setFixedSize(20, 20);
    brand->setAttribute(Qt::WA_TransparentForMouseEvents);
    layout->addWidget(brand);
    auto *title = new QLabel(window_->windowTitle(), this);
    title->setObjectName("windowTitle");
    title->setAttribute(Qt::WA_TransparentForMouseEvents);
    layout->addWidget(title);
    connect(window_, &QWidget::windowTitleChanged, title, &QLabel::setText);
    layout->addStretch();
    auto *buttons = new QWidget(this);
    auto *controls = new QHBoxLayout(buttons);
    controls->setContentsMargins(0, 0, 0, 0);
    controls->setSpacing(0);
    minimize_ = new CaptionButton(Caption::Minimize, window_, buttons);
    maximize_ = new CaptionButton(Caption::Maximize, window_, buttons);
    close_ = new CaptionButton(Caption::Close, window_, buttons);
    minimize_->setObjectName("windowMinimizeButton");
    maximize_->setObjectName("windowMaximizeButton");
    close_->setObjectName("windowCloseButton");
    for (auto *button : {minimize_, maximize_, close_})
        controls->addWidget(button);
    layout->addWidget(buttons);
    connect(minimize_, &QAbstractButton::clicked, window_, &QWidget::showMinimized);
    connect(maximize_, &QAbstractButton::clicked, this, &WindowTitleBar::toggleMaximized);
    connect(close_, &QAbstractButton::clicked, window_, &QWidget::close);
    connect(&i18n::language(), &i18n::Language::changed, this, &WindowTitleBar::refresh);
    window_->installEventFilter(this);
    refresh();
}
void WindowTitleBar::refresh() {
    for (const auto &entry :
         {std::pair{minimize_, QString("最小化")},
          std::pair{maximize_, QString(window_->isMaximized() ? "还原" : "最大化")},
          std::pair{close_, QString("关闭")}}) {
        const auto text = i18n::text(entry.second);
        entry.first->setToolTip(text);
        entry.first->setAccessibleName(text);
        entry.first->update();
    }
    if (auto *brand = findChild<QLabel *>("windowBrand"))
        brand->setPixmap(
            icons::icon(icons::Id::Brand, false, 20).pixmap(QSize(20, 20), devicePixelRatioF()));
}
bool WindowTitleBar::eventFilter(QObject *watched, QEvent *event) {
    if (watched == window_ &&
        (event->type() == QEvent::WindowStateChange || event->type() == QEvent::PaletteChange ||
         event->type() == QEvent::StyleChange))
        refresh();
    return QWidget::eventFilter(watched, event);
}
void WindowTitleBar::toggleMaximized() {
    if (window_->isMaximized())
        window_->showNormal();
    else
        window_->showMaximized();
}
bool WindowTitleBar::isDragArea(const QPoint &windowPosition) const {
    const auto position = mapFrom(window_, windowPosition);
    if (!rect().contains(position))
        return false;
    auto *child = childAt(position);
    while (child && child != this) {
        if (qobject_cast<QAbstractButton *>(child))
            return false;
        child = child->parentWidget();
    }
    return true;
}
void WindowTitleBar::mousePressEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton && window_->windowHandle()) {
        window_->windowHandle()->startSystemMove();
        event->accept();
        return;
    }
    QWidget::mousePressEvent(event);
}
void WindowTitleBar::mouseDoubleClickEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton) {
        toggleMaximized();
        event->accept();
        return;
    }
    QWidget::mouseDoubleClickEvent(event);
}
void WindowTitleBar::contextMenuEvent(QContextMenuEvent *event) {
    QMenu menu(this);
    auto *restore = menu.addAction(i18n::text("还原"));
    restore->setEnabled(window_->isMaximized());
    connect(restore, &QAction::triggered, window_, &QWidget::showNormal);
    connect(menu.addAction(i18n::text("最小化")), &QAction::triggered, window_,
            &QWidget::showMinimized);
    auto *maximize = menu.addAction(i18n::text("最大化"));
    maximize->setEnabled(!window_->isMaximized());
    connect(maximize, &QAction::triggered, window_, &QWidget::showMaximized);
    menu.addSeparator();
    auto *close = menu.addAction(i18n::text("关闭"));
    close->setShortcut(QKeySequence(Qt::ALT | Qt::Key_F4));
    connect(close, &QAction::triggered, window_, &QWidget::close);
    menu.exec(event->globalPos());
}
} // namespace etherscope
