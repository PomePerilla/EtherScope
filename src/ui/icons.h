#pragma once
#include <QIcon>
#include <QPainter>
class QAction;
class QAbstractButton;
class QWidget;
namespace etherscope::icons {
enum class Id {
    Brand,
    Start,
    Stop,
    Open,
    Save,
    Refresh,
    Filter,
    Expression,
    Tcp,
    Application,
    Key,
    Record,
    Chart,
    Diagnostic,
    Locate,
    More,
    Theme,
    Language,
    Close,
    Warning,
    Error
};
QIcon icon(Id id, bool primary = false, int size = 20);
void bind(QAbstractButton *button, Id id, bool primary = false);
void bind(QAction *action, Id id);
void refresh(QWidget *root);
void drawBrand(QPainter &p, const QColor &color, bool small = false);
} // namespace etherscope::icons
