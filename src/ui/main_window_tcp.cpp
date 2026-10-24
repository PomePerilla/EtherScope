#include "ui/main_window.h"
#include "ui/tcp_dialog.h"
#include "ui/analysis_dock.h"
#include <QCheckBox>
#include <QComboBox>
#include <QSignalBlocker>
#include <QTableView>
#include <algorithm>

namespace etherscope {
void MainWindow::refreshTcpConversations() { refreshAnalysisSources(); }
void MainWindow::bindTcpSource() {
    tcpContext_ = sourceContext(view_);
    tcpSourceName_ = sourceNames_[view_];
    tcpInvalidated_ = false;
    tcpDialog_->setSourceContext(tcpContext_);
    tcpDock_->showError({});
    tcpDialog_->setEnabled(true);
    refreshAnalysisSources();
    if (selected_ && selected_->tcpConversationId)
        tcpDialog_->selectConversation(selected_->tcpConversationId);
}
void MainWindow::showTcpConversations() {
    if (closing_)
        return;
    if (!tcpDialog_) {
        tcpDock_ = createAnalysisDock("TCP 会话", "tcpAnalysisDock");
        tcpDialog_ = new TcpPanel(tcpDock_, streamDecoder_);
        tcpDock_->setContent(tcpDialog_);
        tcpDock_->closeContent = [this] { return tcpDialog_->close(); };
        connect(tcpDialog_, &TcpPanel::closed, tcpDock_, &QWidget::hide);
        connect(tcpDock_, &AnalysisDock::rebindRequested, this, &MainWindow::bindTcpSource);
        connect(tcpDialog_, &TcpPanel::analysisHelpRequested, this, &MainWindow::showAnalysisHelp);
        connect(tcpDialog_, &TcpPanel::expressionRequested, this,
                [this](const QString &predicate, bool unique, SourceContext context) {
                    if (context.session == view_ && sourceValid(context, true)) applyQuickFilter(predicate, unique);
                    else tcpDock_->showError("筛选来源已失效");
                });
        connect(tcpDialog_, &TcpPanel::workChanged, this, &MainWindow::tryClose);
        connect(tcpDialog_, &TcpPanel::filterRequested, this,
                [this](quint64 id, quint64 generation, const SessionStore *store) {
                    if (closing_ || store != &currentStore() ||
                        generation != store->tcp().generation() || !store->tcp().find(id))
                        return;
                    auto filter = model_->filter();
                    filter.protocol = "TCP";
                    filter.icmpType.reset();
                    filter.tcpConversationId = id;
                    if (std::none_of(store->packets().begin(), store->packets().end(),
                                     [&](const auto &packet) { return filter.matches(*packet); })) {
                        tcpDialog_->showError("无匹配报文");
                        return;
                    }
                    {
                        QSignalBlocker block(protocol_);
                        protocol_->setCurrentText("TCP");
                    }
                    commitFilter(std::move(filter));
                    follow_->setChecked(false);
                    tcpDock_->showError({});
                });
        connect(tcpDialog_, &TcpPanel::locateRequested, this,
                [this](quint64 id, quint64 generation, const SessionStore *store) {
                    if (closing_ || store != &currentStore() ||
                        generation != store->tcp().generation()) {
                        tcpDock_->showError("分析来源已变化，请切回来源或重新分析");
                        return;
                    }
                    const auto row = model_->rowForId(id);
                    if (row < 0) {
                        const bool retained =
                            std::any_of(store->packets().begin(), store->packets().end(),
                                        [id](const auto &packet) { return packet->id == id; });
                        tcpDialog_->showError(retained ? "报文已被筛选" : "报文已覆盖");
                        return;
                    }
                    actionError_.clear();
                    follow_->setChecked(false);
                    selectPacket(row);
                    table_->scrollTo(model_->index(row, 0));
                    tcpDock_->showError({});
                    raise();
                    activateWindow();
                });
        bindTcpSource();
    }
    refreshTcpConversations();
    tcpDialog_->show();
    presentAnalysisDock(tcpDock_);
}
} // namespace etherscope
