#pragma once
#include <QColor>
#include <QStyle>
#include <QWidget>

namespace etherscope::style {
inline constexpr int gap = 6;
inline constexpr int margin = 8;
inline constexpr int controlHeight = 28;
inline constexpr int titleHeight = 24;
inline constexpr auto danger = "#ed6b65";
inline constexpr auto amber = "#cca700";
inline constexpr auto lightAmber = "#886500";
inline QColor warning(bool dark) {
    return QColor(dark ? amber : lightAmber);
}
inline void setFlag(QWidget *widget, const char *name, bool value) {
    if (widget->property(name).toBool() == value)
        return;
    widget->setProperty(name, value);
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    widget->update();
}
} // namespace etherscope::style
