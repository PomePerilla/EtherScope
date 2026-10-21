#include "ui/main_window.h"
#include "ui/style.h"
#include <QAction>
#include <QApplication>
#include <QSignalBlocker>

namespace etherscope {
void MainWindow::setDarkTheme(bool dark) {
    dark_ = dark;
    QPalette palette;
    const QString bg = dark ? "#101010" : "#f3f4f6", base = dark ? "#151515" : "#ffffff";
    const QString text = dark ? "#d0d0d0" : "#24282e", muted = dark ? "#929292" : "#66717c";
    const QString border = dark ? "#303030" : "#d6dbe1", bar = dark ? "#1b1b1b" : "#edf0f3";
    const QString accent = style::warning(dark).name(), selection = dark ? "#233448" : "#dce9f6",
                  hover = dark ? "#242424" : "#e7ecf1";
    palette.setColor(QPalette::Window, QColor(bg));
    palette.setColor(QPalette::WindowText, QColor(text));
    palette.setColor(QPalette::Base, QColor(base));
    palette.setColor(QPalette::AlternateBase, QColor(dark ? "#181818" : "#f7f8fa"));
    palette.setColor(QPalette::Text, QColor(text));
    palette.setColor(QPalette::Button, QColor(bar));
    palette.setColor(QPalette::ButtonText, QColor(text));
    palette.setColor(QPalette::PlaceholderText, QColor(muted));
    palette.setColor(QPalette::Highlight, QColor(selection));
    palette.setColor(QPalette::HighlightedText, QColor(text));
    palette.setColor(QPalette::Mid, QColor(border));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText,
                     QColor(dark ? "#646464" : "#9da5af"));
    qApp->setPalette(palette);
    qApp->setStyleSheet(QString(R"(
        QWidget { font-family: 'Segoe UI', 'Microsoft YaHei UI'; font-size: 12px; }
        QWidget#workspace { background: %1; }
        QWidget#toolbarBar, QWidget#sessionStrip, QWidget#addressFilterPanel { background: %2; border-bottom: 1px solid %3; }
        QLabel#panelTitle { color: %4; background: %1; padding-left: 8px; }
        QWidget#detailHeader, QWidget#diagnosticPanel { background: %1; color: %4; border-top: 1px solid %3; }
        QLabel[error="true"] { color: %11; }
        QPushButton { min-height: %12px; padding: 0 9px; border: 1px solid transparent; border-radius: 2px; background: transparent; }
        QPushButton:hover { background: %8; }
        QPushButton:focus { border-color: %6; }
        QPushButton:checked { color: %6; background: %8; }
        QPushButton[accent="true"] { background: %6; color: %1; font-weight: bold; }
        QPushButton#stopButton:enabled { color: %11; }
        QPushButton:disabled { color: %9; }
        QPushButton[condition="true"] { background: %5; color: %4; padding: 0 6px; }
        QPushButton[condition="true"]:hover { background: %8; color: %7; }
        QLabel[warning="true"], QPushButton[warning="true"] { color: %6; }
        QPushButton::menu-indicator { subcontrol-position: right center; right: 3px; width: 5px; }
        QLineEdit, QComboBox { min-height: %12px; padding: 0 6px; border: 1px solid %3; border-radius: 2px; background: %5; }
        QLineEdit:focus, QComboBox:focus { border-color: %6; }
        QLineEdit[invalid="true"] { border-color: %11; }
        QComboBox::drop-down { width: 18px; border: none; }
        QComboBox::down-arrow { image: url(:/icons/chevron-down.xpm); width: 9px; height: 5px; }
        QComboBox QAbstractItemView { background: %5; border: 1px solid %3; selection-background-color: %10; padding: 3px; }
        QTableView, QTreeWidget, QPlainTextEdit { border: none; background: %5; selection-background-color: %10; }
        QTableView::item, QTreeWidget::item { padding: 2px 5px; }
        QTreeWidget::item { min-height: 21px; }
        QTableView::item:selected, QTreeWidget::item:selected { background: %10; color: %7; }
        QTableView:focus, QTreeWidget:focus, QPlainTextEdit:focus { border: 1px solid %6; }
        QHeaderView::section { background: %2; color: %4; padding: 3px 7px; border: none; border-bottom: 1px solid %3; }
        QTabWidget::pane { border: none; background: %1; }
        QWidget#streamPane { background: %1; }
        QTabBar::tab { min-width: 36px; padding: 5px 8px; background: transparent; color: %4; border-bottom: 2px solid transparent; }
        QTabBar::tab:selected { color: %7; border-bottom-color: %6; }
        QTabBar::tab:hover { background: %8; }
        QCheckBox { spacing: 5px; color: %4; }
        QCheckBox:focus { color: %7; }
        QCheckBox::indicator { width: 11px; height: 11px; border: 1px solid %4; background: %5; }
        QCheckBox::indicator:checked { background: %6; border-color: %6; }
        QSplitter::handle { background: %3; width: 2px; height: 2px; }
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
        QToolTip { color: %7; background: %2; border: 1px solid %3; padding: 4px; }
        QPlainTextEdit#hexView, QPlainTextEdit#streamBytes, QPlainTextEdit#applicationBytes { font-family: 'Consolas', 'Courier New'; font-size: 12px; padding: 6px; }
    )")
                            .arg(bg, bar, border, muted, base, accent, text, hover,
                                 dark ? "#646464" : "#9da5af", selection, style::danger,
                                 QString::number(style::controlHeight - 2)));
    {
        QSignalBlocker block(theme_);
        theme_->setChecked(dark);
    }
    updateStatus();
}
} // namespace etherscope
