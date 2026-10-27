#include "ui/main_window.h"
#include "ui/analysis_dock.h"
#include "ui/application_view.h"
#include "ui/tcp_dialog.h"
#include "ui/language.h"
#include <QApplication>
#include <QComboBox>
#include <QScreen>
#include <QScopedValueRollback>
#include <QSettings>
#include <QTabBar>
#include <algorithm>

namespace etherscope {
SessionStore &MainWindow::storeFor(int session) { return session == 0 ? live_ : file_; }
SourceContext MainWindow::sourceContext(int session) const {
    const auto &store = session == 0 ? live_ : file_;
    return {session, store.tcp().generation(),
            applications_[session] ? applications_[session]->generation() : 0};
}
bool MainWindow::sourceValid(const SourceContext &context, bool analysis) const {
    if (context.session < 0 || context.session > 1) return false;
    const auto current = sourceContext(context.session);
    return current.generation == context.generation &&
           (!analysis || current.analysisGeneration == context.analysisGeneration);
}
QString MainWindow::sourceName(int session) const {
    const auto type = i18n::text(session == 0 ? "实时" : "文件");
    return type + (sourceNames_[session].isEmpty() ? QString{} : ": " + sourceNames_[session]);
}
AnalysisDock *MainWindow::createAnalysisDock(const QString &title, const QString &name) {
    auto *dock = new AnalysisDock(title, name, analysisWorkspace_);
    const QScopedValueRollback<bool> arranging(arrangingDocks_, true);
    const auto prefix = "ui/analysis/v1/" + name + "/";
    const bool wide = analysisWorkspace_->width() >= 1280 && analysisWorkspace_->height() >= 600;
    dock->preferredFloating = settings_->value(prefix + "floating", false).toBool();
    const auto area = settings_->value(prefix + "area", int(Qt::RightDockWidgetArea)).toInt();
    dock->preferredArea = area == Qt::BottomDockWidgetArea ? Qt::BottomDockWidgetArea
                                                         : Qt::RightDockWidgetArea;
    analysisWorkspace_->addDockWidget(dock->preferredArea, dock);
    dock->hide();
    dock->setFloating(dock->preferredFloating || !wide);
    dock->automaticFloating = !dock->preferredFloating && !wide;
    const auto geometry = settings_->value(prefix + "geometry").toByteArray();
    if (!geometry.isEmpty()) dock->restoreGeometry(geometry);
    else dock->resize(1000, 650);
    dock->initialized = true;
    connect(dock, &QDockWidget::topLevelChanged, this, [this, dock](bool floating) {
        if (arrangingDocks_) return;
        dock->preferredFloating = floating;
        dock->automaticFloating = false;
        if (!floating) {
            const auto area = analysisWorkspace_->dockWidgetArea(dock);
            if (area == Qt::RightDockWidgetArea || area == Qt::BottomDockWidgetArea)
                dock->preferredArea = area;
        }
        QTimer::singleShot(0, this, &MainWindow::arrangeAnalysisDocks);
    });
    connect(dock, &QDockWidget::dockLocationChanged, this, [this, dock](Qt::DockWidgetArea area) {
        if (!arrangingDocks_ && (area == Qt::RightDockWidgetArea || area == Qt::BottomDockWidgetArea))
            dock->preferredArea = area;
    });
    connect(dock, &QDockWidget::visibilityChanged, this, [this] {
        QTimer::singleShot(0, this, &MainWindow::arrangeAnalysisDocks);
    });
    return dock;
}
void MainWindow::presentAnalysisDock(AnalysisDock *dock) {
    dock->widget()->show();
    dock->show();
    if (!dock->isFloating()) {
        for (auto *other : {tcpDock_, applicationDock_})
            if (other && other != dock && !other->isFloating() && !other->isHidden() &&
                analysisWorkspace_->dockWidgetArea(other) == analysisWorkspace_->dockWidgetArea(dock))
                analysisWorkspace_->tabifyDockWidget(other, dock);
        const auto prefix = "ui/analysis/v1/" + dock->objectName() + "/";
        const auto extent = std::clamp(settings_->value(prefix + "extent", 520).toInt(), 320, 1200);
        analysisWorkspace_->resizeDocks({dock}, {extent},
            dock->preferredArea == Qt::BottomDockWidgetArea ? Qt::Vertical : Qt::Horizontal);
    }
    arrangeAnalysisDocks();
    dock->raise();
    if (dock->isFloating()) dock->activateWindow();
}
void MainWindow::arrangeAnalysisDocks() {
    if (!analysisWorkspace_ || arrangingDocks_) return;
    const QScopedValueRollback<bool> arranging(arrangingDocks_, true);
    const auto size = analysisWorkspace_->size();
    for (auto *dock : {tcpDock_, applicationDock_}) {
        if (!dock || dock->isHidden()) continue;
        const bool fits = dock->preferredArea == Qt::BottomDockWidgetArea
                              ? size.width() >= 720 && size.height() >= 360 + 350
                              : size.width() >= 1280 && size.height() >= 600;
        if (!dock->preferredFloating && !fits && !dock->isFloating()) {
            dock->automaticFloating = true;
            dock->setFloating(true);
            dock->resize(1000, 650);
        } else if (dock->automaticFloating && fits) {
            dock->automaticFloating = false;
            analysisWorkspace_->addDockWidget(dock->preferredArea, dock);
            dock->setFloating(false);
            analysisWorkspace_->resizeDocks({dock}, {520},
                dock->preferredArea == Qt::BottomDockWidgetArea ? Qt::Vertical : Qt::Horizontal);
            for (auto *other : {tcpDock_, applicationDock_})
                if (other && other != dock && !other->isFloating() && !other->isHidden() &&
                    other->preferredArea == dock->preferredArea)
                    analysisWorkspace_->tabifyDockWidget(other, dock);
        }
        if (dock->isFloating()) {
            auto *screen = QGuiApplication::screenAt(dock->frameGeometry().center());
            if (!screen) screen = QGuiApplication::primaryScreen();
            if (!screen) continue;
            const auto bounds = screen->availableGeometry().adjusted(8, 30, -8, -8);
            dock->resize(std::min(dock->width(), bounds.width()),
                         std::min(dock->height(), bounds.height()));
            dock->move(std::clamp(dock->x(), bounds.left(), std::max(bounds.left(), bounds.right() - dock->width())),
                       std::clamp(dock->y(), bounds.top(), std::max(bounds.top(), bounds.bottom() - dock->height())));
        }
    }
    for (auto *dock : {tcpDock_, applicationDock_}) {
        if (!dock) continue;
        const auto peers = analysisWorkspace_->tabifiedDockWidgets(dock);
        const bool tabbed = !dock->isFloating() && std::any_of(peers.begin(), peers.end(),
            [](QDockWidget *peer) { return !peer->isFloating() && !peer->isHidden(); });
        dock->setTabbed(tabbed);
    }
}
void MainWindow::saveAnalysisLayout() {
    for (auto *dock : {tcpDock_, applicationDock_}) {
        if (!dock || !dock->initialized) continue;
        const auto prefix = "ui/analysis/v1/" + dock->objectName() + "/";
        settings_->setValue(prefix + "floating", dock->preferredFloating);
        settings_->setValue(prefix + "area", int(dock->preferredArea));
        if (dock->isFloating()) settings_->setValue(prefix + "geometry", dock->saveGeometry());
        else settings_->setValue(prefix + "extent",
            dock->preferredArea == Qt::BottomDockWidgetArea ? dock->height() : dock->width());
    }
}
void MainWindow::resetAnalysisLayout() {
    settings_->remove("ui/analysis/v1");
    const QScopedValueRollback<bool> arranging(arrangingDocks_, true);
    const bool wide = analysisWorkspace_->width() >= 1280 && analysisWorkspace_->height() >= 600;
    AnalysisDock *first = nullptr;
    for (auto *dock : {tcpDock_, applicationDock_}) {
        if (!dock) continue;
        dock->preferredArea = Qt::RightDockWidgetArea;
        dock->preferredFloating = false;
        dock->automaticFloating = !wide;
        analysisWorkspace_->addDockWidget(Qt::RightDockWidgetArea, dock);
        dock->setFloating(!wide);
        if (wide) {
            analysisWorkspace_->resizeDocks({dock}, {520}, Qt::Horizontal);
            if (first) analysisWorkspace_->tabifyDockWidget(first, dock);
            first = dock;
        } else dock->resize(1000, 650);
    }
    QTimer::singleShot(0, this, &MainWindow::arrangeAnalysisDocks);
}
void MainWindow::refreshAnalysisSources() {
    if (tcpDock_ && tcpContext_.session >= 0) {
        const bool valid = sourceValid(tcpContext_);
        if (valid) {
            tcpDialog_->refresh(storeFor(tcpContext_.session), tcpContext_.session == 0 ? "实时" : "文件");
            tcpDialog_->updateAnalysisContext(sourceContext(tcpContext_.session));
            tcpDialog_->setApplicationIndex(&applicationIndex_[tcpContext_.session]);
        } else if (!tcpInvalidated_) {
            tcpInvalidated_ = true;
            tcpDialog_->invalidate();
        }
        const bool current = valid && tcpContext_.session == view_;
        tcpDialog_->setNavigationEnabled(current);
        const auto conversation = tcpDialog_->selectedConversation();
        tcpDock_->setSource(i18n::text(tcpContext_.session == 0 ? "实时" : "文件") +
                            (tcpSourceName_.isEmpty() ? QString{} : ": " + tcpSourceName_),
                            conversation ? QString("#%1").arg(conversation) : QString{});
        if (!valid) tcpDock_->showError("来源已重置，请重新分析");
        else if (!current) tcpDock_->showError("来源不同，请切回对应的实时或文件视图后定位");
        else if (tcpDock_->property("sourceMismatch").toBool()) tcpDock_->showError({});
        tcpDock_->setProperty("sourceMismatch", !current);
    }
    if (applicationDock_ && applicationContext_.session >= 0) {
        const bool valid = sourceValid(applicationContext_, true);
        if (valid)
            applicationView_->setResults(applicationIndex_[applicationContext_.session].results(applicationPacket_));
        else if (!applicationInvalidated_) {
            applicationInvalidated_ = true;
            applicationView_->setResults({});
        }
        const bool current = valid && applicationContext_.session == view_;
        applicationView_->setNavigationEnabled(current);
        applicationDock_->setSource(i18n::text(applicationContext_.session == 0 ? "实时" : "文件") +
                                    (applicationSourceName_.isEmpty() ? QString{} : ": " + applicationSourceName_),
                                    QString("#%1").arg(applicationPacket_));
        if (!valid) applicationDock_->showError("来源已重置，请重新分析");
        else if (!current) applicationDock_->showError("来源不同，请切回对应的实时或文件视图后定位");
        else if (applicationDock_->property("sourceMismatch").toBool()) applicationDock_->showError({});
        applicationDock_->setProperty("sourceMismatch", !current);
    }
}
} // namespace etherscope
