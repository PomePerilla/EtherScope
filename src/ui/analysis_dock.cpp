#include "ui/analysis_dock.h"
#include "ui/language.h"
#include "ui/icons.h"
#include <QCloseEvent>
#include <QResizeEvent>
#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QScopedValueRollback>
#include <QTimer>
namespace etherscope {
AnalysisDock::AnalysisDock(const QString &title, const QString &name, QWidget *parent)
    : QDockWidget(title, parent) {
    setObjectName(name);
    setAllowedAreas(Qt::RightDockWidgetArea | Qt::BottomDockWidgetArea);
    body_ = new QWidget(this);
    body_->setMinimumSize(480, 320);
    auto *layout = new QVBoxLayout(body_);
    layout->setContentsMargins(8, 4, 8, 4);
    layout->setSpacing(4);
    header_ = new QWidget(this);
    header_->setObjectName(name + "Header");
    header_->setProperty("analysisHeader", true);
    auto *bar = new QHBoxLayout(header_);
    bar->setContentsMargins(8, 0, 4, 0);
    bar->setSpacing(4);
    title_ = new QLabel(title, header_);
    title_->setObjectName(name + "Title");
    bar->addWidget(title_);
    source_ = new QLabel(header_);
    source_->setObjectName(name + "Source");
    source_->setMinimumWidth(40);
    source_->setTextFormat(Qt::PlainText);
    source_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    bar->addWidget(source_, 1);
    identity_ = new QLabel(header_);
    identity_->setObjectName(name + "Identity");
    bar->addWidget(identity_);
    auto *rebind = new QPushButton("分析当前来源", header_);
    rebind->setObjectName(name + "Rebind");
    bar->addWidget(rebind);
    float_ = new QPushButton(header_);
    float_->setObjectName(name + "Float");
    float_->setFixedWidth(30);
    bar->addWidget(float_);
    close_ = new QPushButton(header_);
    close_->setObjectName(name + "Close");
    close_->setFixedWidth(30);
    icons::bind(close_, icons::Id::Close);
    close_->setToolTip("关闭面板");
    close_->setAccessibleName("关闭面板");
    bar->addWidget(close_);
    error_ = new QLabel(body_);
    error_->setObjectName(name + "Error");
    error_->setTextFormat(Qt::PlainText);
    error_->setWordWrap(true);
    error_->setProperty("error", true);
    error_->hide();
    layout->addWidget(error_);
    setWidget(body_);
    setTitleBarWidget(header_);
    connect(rebind, &QPushButton::clicked, this, &AnalysisDock::rebindRequested);
    connect(float_, &QPushButton::clicked, this, [this] { setFloating(!isFloating()); });
    connect(close_, &QPushButton::clicked, this, &QWidget::close);
    connect(this, &QDockWidget::topLevelChanged, this, [this] { syncHeader(); });
    i18n::bind(this);
    connect(&i18n::language(), &i18n::Language::changed, this, &AnalysisDock::syncHeader);
    syncHeader();
}
void AnalysisDock::setContent(QWidget *content) {
    static_cast<QVBoxLayout *>(body_->layout())->addWidget(content, 1);
}
void AnalysisDock::setSource(const QString &source, const QString &identity) {
    if (sourceText_ == source && identity_->text() == identity) return;
    sourceText_ = source;
    source_->setToolTip(source + (identity.isEmpty() ? QString{} : " / " + identity));
    identity_->setText(identity);
    identity_->setVisible(!identity.isEmpty());
    elideSource();
}
void AnalysisDock::setTabbed(bool tabbed) {
    if (tabbed_ == tabbed) return;
    tabbed_ = tabbed;
    syncHeader();
}
void AnalysisDock::elideSource() {
    source_->setText(source_->fontMetrics().elidedText(sourceText_, Qt::ElideMiddle, source_->width()));
}
void AnalysisDock::syncHeader() {
    if (syncing_) return;
    const QScopedValueRollback<bool> syncing(syncing_, true);
    auto *layout = static_cast<QVBoxLayout *>(body_->layout());
    if (isFloating()) {
        if (titleBarWidget() == header_) {
            setTitleBarWidget(nullptr);
            layout->insertWidget(0, header_);
        }
    } else if (titleBarWidget() != header_) {
        layout->removeWidget(header_);
        setTitleBarWidget(header_);
    }
    title_->setVisible(!isFloating() && !tabbed_);
    close_->setVisible(!isFloating());
    icons::bind(float_, isFloating() ? icons::Id::Dock : icons::Id::Float);
    const auto caption = i18n::text(isFloating() ? "停靠面板" : "浮动面板");
    float_->setToolTip(caption);
    float_->setAccessibleName(caption);
    header_->show();
    QTimer::singleShot(0, this, &AnalysisDock::elideSource);
}
void AnalysisDock::resizeEvent(QResizeEvent *event) {
    QDockWidget::resizeEvent(event);
    elideSource();
    QTimer::singleShot(0, this, &AnalysisDock::elideSource);
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
