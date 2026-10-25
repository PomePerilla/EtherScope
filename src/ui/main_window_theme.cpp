#include "ui/main_window.h"
#include "ui/style.h"
#include "ui/icons.h"
#include <QAction>
#include <QApplication>
#include <QLabel>
#include <QTreeWidget>
#include <QSignalBlocker>

namespace etherscope {
void MainWindow::setDarkTheme(bool dark) {
    dark_ = dark;
    QPalette palette;
    const auto c = style::colors(dark);
    const QString bg = c.background, base = c.base, text = c.text, muted = c.muted;
    const QString border = c.border, bar = c.bar, accent = c.accent, selection = c.selection,
                  hover = c.hover;
    palette.setColor(QPalette::Window, QColor(bg));
    palette.setColor(QPalette::WindowText, QColor(text));
    palette.setColor(QPalette::Base, QColor(base));
    palette.setColor(QPalette::AlternateBase, QColor(c.alternate));
    palette.setColor(QPalette::Text, QColor(text));
    palette.setColor(QPalette::Button, QColor(bar));
    palette.setColor(QPalette::ButtonText, QColor(text));
    palette.setColor(QPalette::PlaceholderText, QColor(muted));
    palette.setColor(QPalette::Highlight, QColor(selection));
    palette.setColor(QPalette::HighlightedText, QColor(text));
    palette.setColor(QPalette::Mid, QColor(border));
    palette.setColor(QPalette::Link, QColor(c.accent));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(c.disabled));
    palette.setColor(QPalette::Disabled, QPalette::Text, QColor(c.disabled));
    palette.setColor(QPalette::ToolTipBase, QColor(bar));
    palette.setColor(QPalette::ToolTipText, QColor(text));
    qApp->setPalette(palette);
    qApp->setStyleSheet(QString(R"(
        QWidget { font-family: 'Segoe UI', 'Microsoft YaHei UI'; font-size: 13px; }
        QMainWindow#mainWindow { background: %1; border: 1px solid %3; }
        QMainWindow#mainWindow[frameMaximized="true"] { border: none; }
        QWidget#windowTitleBar { background: %1; }
        QLabel#windowTitle { color: %7; font-weight: 600; }
        QWidget#workspace { background: %1; }
        QWidget#toolbarBar, QWidget#sessionStrip, QWidget#addressFilterPanel { background: %2; border-bottom: 1px solid %3; }
        QLabel#panelTitle { color: %4; background: %1; padding-left: 8px; }
        QWidget[analysisHeader="true"] { background: %2; border-bottom: 1px solid %3; }
        QWidget[analysisHeader="true"] QLabel { color: %4; }
        QTextEdit[explanation="true"] { background: %2; color: %7; border: none; border-top: 1px solid %3; }
        QPushButton[statusBadge="true"] { background: %2; border: 1px solid %3; }
        QPushButton[statusBadge="true"][statusTone="success"] { color: %14; }
        QPushButton[statusBadge="true"][statusTone="warning"] { color: %6; }
        QPushButton[statusBadge="true"][statusTone="error"] { color: %11; }
        QPushButton[statusBadge="true"]:checked { background: %10; border-color: %6; }
        QWidget#detailHeader, QWidget#diagnosticPanel { background: %1; color: %4; border-top: 1px solid %3; }
        QLabel[error="true"] { color: %11; }
        QPushButton, QToolButton { min-height: %12px; padding: 0 8px; border: 1px solid transparent; border-radius: 4px; background: transparent; }
        QPushButton:hover { background: %8; }
        QToolButton:hover { background: %8; }
        QPushButton:pressed, QToolButton:pressed { background: %10; border-color: %6; }
        QToolButton:focus { border-color: %6; }
        QPushButton:focus { border-color: %6; }
        QPushButton:checked { color: %6; background: %8; }
        QPushButton[accent="true"] { background: %13; color: #16181B; font-weight: 600; }
        QPushButton[accent="true"]:hover { background: #E7C654; }
        QPushButton[accent="true"]:pressed { background: #C6A12C; }
        QPushButton[accent="true"]:disabled { background: %8; color: %9; }
        QPushButton#stopButton:enabled { color: %11; }
        QPushButton:disabled { color: %9; }
        QPushButton[condition="true"] { background: %5; color: %4; padding: 0 6px; }
        QPushButton[condition="true"]:hover { background: %8; color: %7; }
        QLabel[warning="true"], QPushButton[warning="true"] { color: %6; }
        QLabel[success="true"] { color: %14; }
        QLabel#emptyTitle { color: %7; font-weight: 600; }
        QLabel#emptyHint, QLabel#fieldEmptyState { color: %4; }
        QLabel#bpfMarker { color: %6; padding: 2px 4px; }
        QPushButton::menu-indicator { subcontrol-position: right center; right: 3px; width: 5px; }
        QLineEdit, QComboBox { min-height: %12px; padding: 0 6px; border: 1px solid %3; border-radius: 4px; background: %5; }
        QLineEdit:focus, QComboBox:focus { border-color: %6; }
        QLineEdit[invalid="true"] { border-color: %11; }
        QComboBox::drop-down { width: 18px; border: none; }
        QComboBox::down-arrow { image: url(:/icons/chevron-down.xpm); width: 9px; height: 5px; }
        QComboBox QAbstractItemView { background: %5; border: 1px solid %3; selection-background-color: %10; padding: 3px; }
        QTableView, QTreeWidget, QPlainTextEdit { border: none; background: %5; selection-background-color: %10; }
        QTableView::item, QTreeWidget::item { padding: 2px 5px; }
        QTreeWidget::item { min-height: 22px; }
        QTableView::item:selected, QTreeWidget::item:selected { background: %10; color: %7; }
        QTableView, QTreeWidget, QPlainTextEdit { border: 1px solid transparent; }
        QTableView:focus, QTreeWidget:focus, QPlainTextEdit:focus { border-color: %6; }
        QHeaderView::section { background: %2; color: %4; padding: 3px 7px; border: none; border-bottom: 1px solid %3; }
        QTabWidget::pane { border: none; background: %1; }
        QWidget#streamPane { background: %1; }
        QTabBar::tab { min-width: 36px; padding: 5px 8px; background: transparent; color: %4; border-bottom: 2px solid transparent; }
        QTabBar::tab:selected { color: %7; border-bottom-color: %6; }
        QTabBar::tab:hover { background: %8; }
        QCheckBox { spacing: 5px; color: %4; }
        QCheckBox:focus { color: %7; }
        QCheckBox::indicator { width: 12px; height: 12px; border-radius: 2px; border: 1px solid %4; background: %5; }
        QCheckBox::indicator:checked { background: %6; border-color: %6; }
        QSplitter::handle { background: %1; width: 5px; height: 5px; }
        QSplitter::handle:horizontal { border-left: 1px solid %3; }
        QSplitter::handle:vertical { border-top: 1px solid %3; }
        QSplitter::handle:hover { background: %10; }
        QScrollBar:vertical { width: 8px; background: %5; margin: 0; }
        QScrollBar:horizontal { height: 8px; background: %5; margin: 0; }
        QScrollBar::handle { background: %3; min-height: 24px; min-width: 24px; }
        QScrollBar::handle:hover { background: %4; }
        QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
        QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
        QStatusBar { background: %1; border-top: 1px solid %3; color: %4; }
        QStatusBar::item { border: none; }
        QMenu { color: %7; background: %2; border: 1px solid %3; padding: 4px; }
        QMenu::item { padding: 5px 20px; }
        QMenu::item:selected { background: %10; }
        QMenu::item:disabled { color: %4; }
        QMenu::separator { height: 1px; background: %3; margin: 4px 8px; }
        QDialog { background: %1; }
        QSpinBox { min-height: %12px; border: 1px solid %3; border-radius: 4px; background: %5; padding: 0 6px; }
        QToolTip { color: %7; background: %2; border: 1px solid %3; padding: 4px; }
        QPlainTextEdit#hexView, QPlainTextEdit#streamBytes, QPlainTextEdit#applicationBytes { font-family: 'Consolas', 'Courier New'; font-size: 13px; padding: 8px; }
    )")
                            .arg(bg, bar, border, muted, base, accent, text, hover, c.disabled,
                                 selection, c.error, QString::number(style::controlHeight - 2),
                                 style::primary, c.success));
    icons::refresh(this);
    if (auto *brand = findChild<QLabel *>("windowBrand"))
        brand->setPixmap(
            icons::icon(icons::Id::Brand, false, 20).pixmap(QSize(20, 20), devicePixelRatioF()));
    configureNativeFrame();
    if (selected_ && fields_->currentItem())
        highlightBytes(fields_->currentItem(), false);
    {
        QSignalBlocker block(theme_);
        theme_->setChecked(dark);
    }
    updateStatus();
}
} // namespace etherscope
