#include "ui/filter_chip.h"
#include <QResizeEvent>
#include <algorithm>

namespace etherscope {
FilterChip::FilterChip(QWidget* parent):QPushButton(parent) {
    setProperty("condition",true);
    setSizePolicy(QSizePolicy::Preferred,QSizePolicy::Fixed);
}
void FilterChip::setCondition(const QString& text) {
    condition_=text;setToolTip(text);setAccessibleName(text+"，移除");
    setVisible(!text.isEmpty());updateText();updateGeometry();
}
QSize FilterChip::sizeHint() const {return {std::min(260,fontMetrics().horizontalAdvance(condition_)+36),28};}
QSize FilterChip::minimumSizeHint() const {return {52,28};}
void FilterChip::resizeEvent(QResizeEvent* event) {QPushButton::resizeEvent(event);updateText();}
void FilterChip::updateText() {
    setText(fontMetrics().elidedText(condition_,Qt::ElideRight,std::max(0,width()-32))+" ×");
}
}
