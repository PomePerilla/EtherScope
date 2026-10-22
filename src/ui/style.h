#pragma once
#include <QColor>
#include <QFont>
#include <QStyle>
#include <QWidget>

namespace etherscope::style {
inline constexpr int gap = 8;
inline constexpr int margin = 8;
inline constexpr int controlHeight = 30;
inline constexpr int titleHeight = 28;
inline constexpr int rowHeight = 26;
inline constexpr auto primary = "#D8B43C";
inline constexpr auto danger = "#F0807C";
inline constexpr auto amber = "#E5BC68";
inline constexpr auto lightAmber = "#795B00";
struct Colors {
    QString background, base, text, muted, border, bar, hover, selection, alternate, disabled,
        accent, error, success;
};
inline Colors colors(bool dark) {
    return dark
               ? Colors{"#111315", "#17191C", "#E8EAED", "#A8ADB5", "#34383E", "#1D2024", "#292D32",
                        "#302B1C", "#1B1D21", "#747B85", primary,   danger,    "#69B9A5"}
               : Colors{"#F3F4F6", "#FFFFFF", "#24282E", "#5D6571", "#D4D8DE", "#ECEEF1", "#E1E4E8",
                        "#F6ECC8", "#F8F9FA", "#7B838E", "#795B00", "#B42318", "#246E5B"};
}
inline QFont dataFont() {
    QFont font;
    font.setFamilies({"Consolas", "Cascadia Mono", "Courier New"});
    font.setStyleHint(QFont::Monospace);
    font.setPixelSize(13);
    return font;
}
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
