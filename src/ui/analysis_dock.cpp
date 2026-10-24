#include "ui/analysis_dock.h"
#include "ui/language.h"
#include "ui/flow_layout.h"
#include <QCloseEvent>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
namespace etherscope {
AnalysisDock::AnalysisDock(const QString &title, const QString &name, QWidget *parent)
    : QDockWidget(title, parent) {
    setObjectName(name);
    setAllowedAreas(Qt::RightDockWidgetArea | Qt::BottomDockWidgetArea);
    body_ = new QWidget(this);
    body_->setMinimumSize(480, 320);
    auto *layout = new QVBoxLayout(body_);
    layout->setContentsMargins(8, 4, 8, 4);
    auto *bar = new FlowLayout;
    source_ = new QLabel(body_);
    source_->setObjectName(name + "Source");
    source_->setMinimumWidth(80);
    source_->setMaximumWidth(320);
    source_->setTextFormat(Qt::PlainText);
    auto *rebind = new QPushButton("分析当前来源", body_);
    rebind->setObjectName(name + "Rebind");
    bar->addWidget(source_);
    bar->addWidget(rebind);
    layout->addLayout(bar);
    error_ = new QLabel(body_);
    error_->setObjectName(name + "Error");
    error_->setTextFormat(Qt::PlainText);
    error_->setWordWrap(true);
    error_->setProperty("error", true);
    error_->hide();
    layout->addWidget(error_);
    setWidget(body_);
    connect(rebind, &QPushButton::clicked, this, &AnalysisDock::rebindRequested);
    i18n::bind(this);
}
void AnalysisDock::setContent(QWidget *content) {
    static_cast<QVBoxLayout *>(body_->layout())->addWidget(content, 1);
}
void AnalysisDock::setSource(const QString &source) {
    source_->setToolTip(source);
    source_->setText(source_->fontMetrics().elidedText(source, Qt::ElideMiddle, 310));
}
void AnalysisDock::showError(const QString &message) {
    i18n::setLabel(error_, message);
    error_->setVisible(!message.isEmpty());
}
void AnalysisDock::closeEvent(QCloseEvent *event) {
    if (closeContent && !closeContent()) {
        event->ignore();
        return;
    }
    QDockWidget::closeEvent(event);
}
} // namespace etherscope
