#include "ui/main_window.h"
#include "ui/filter_chip.h"
#include "ui/helpers.h"
#include "ui/language.h"
#include "ui/style.h"
#include "ui/application_view.h"
#include "ui/analysis_dock.h"
#include <QAction>
#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSettings>
#include <QScopedValueRollback>
#include <QSpinBox>
#include <QTableView>
#include <QVBoxLayout>
#include <algorithm>
#include <set>

namespace etherscope {
void MainWindow::initializeAnalysis(const MainWindowOptions &options) {
    for (unsigned i = 0; i < 2; ++i) {
        applications_[i] = std::make_unique<ApplicationAnalysisService>(this, options.application);
        connect(applications_[i].get(), &ApplicationAnalysisService::changed, this,
                &MainWindow::tryClose, Qt::QueuedConnection);
        connect(
            applications_[i].get(), &ApplicationAnalysisService::keyLogChanged, this,
            [this](bool success, const QString &error) {
                if (!success)
                    reportError(error);
            },
            Qt::QueuedConnection);
    }
    model_->setApplicationIndex(&applicationIndex_[view_]);
    connect(&applicationTimer_, &QTimer::timeout, this, &MainWindow::collectApplications);
    applicationTimer_.start(100);
    connect(expressionInput_, &QLineEdit::returnPressed, this,
            [this] { applyExpression(expressionInput_->text()); });
    connect(expressionChip_, &QPushButton::clicked, this, [this] {
        expressionInput_->clear();
        applyExpression({});
    });
    connect(
        &recording_, &RecordingService::finished, this,
        [this](quint64 request, bool success, const QString &error) {
            if (request != recording_.generation())
                return;
            recordingPending_ = false;
            if (!success) {
                closing_ = false;
                reportError(error);
            }
            updateButtons();
            updateStatus();
            tryClose();
        },
        Qt::QueuedConnection);
}
void MainWindow::resetApplications(int session) {
    if (session == view_) filterUndo_.clear();
    refreshFilterHistory();
    applications_[session]->reset();
    applicationIndex_[session].clear();
    applicationSubmitted_[session] = 0;
}
void MainWindow::submitApplications(int session) {
    auto &store = session == 0 ? live_ : file_;
    auto delta = store.deltaAfter(applicationSubmitted_[session]);
    IndexDelta indexDelta;
    applicationIndex_[session].observe(delta, &indexDelta);
    auto packets = std::move(delta.added);
    std::set<std::uint64_t> dirty;
    for (const auto &p : packets) {
        if (p->tcpConversationId)
            dirty.insert(p->tcpConversationId);
    }
    std::vector<TcpConversation> conversations;
    for (auto id : dirty)
        if (const auto *c = store.tcp().find(id))
            conversations.push_back(*c);
    applicationSubmitted_[session] = delta.through;
    applications_[session]->submit(std::move(packets), std::move(conversations),
                                   store.packets().empty() ? 0 : store.packets().front()->id);
    if (session == view_) {
        QScopedValueRollback<bool> changing(updatingSelection_, true);
        model_->refreshApplications(indexDelta);
        showDetails();
    }
}
void MainWindow::collectApplications() {
    bool changed = false;
    IndexDelta delta;
    for (int session = 0; session < 2; ++session) {
        const auto &store = session == 0 ? live_ : file_;
        auto updates = applications_[session]->takeResults();
        for (auto &update : updates)
            if (applications_[session]->accepts(update)) {
                const auto first = store.packets().empty() ? 0 : store.packets().front()->id,
                           last = store.packets().empty() ? 0 : store.packets().back()->id;
                std::erase_if(update.facts, [&](const auto &pair) {
                    return !first || pair.first < first || pair.first > last;
                });
                if (update.limitedOnly) {
                    for (const auto &[id, fact] : update.facts) {
                        (void)fact;
                        applicationIndex_[session].limit(std::span(&id, 1),
                                                         session == view_ ? &delta : nullptr);
                    }
                    changed |= session == view_;
                    continue;
                }
                if (applicationIndex_[session].apply(
                        update.conversation, std::move(update.result), std::move(update.facts),
                        session == view_ ? &delta : nullptr, {update.keyRevision, update.revision}))
                    applicationIndex_[session].limit(update.limitedPackets,
                                                     session == view_ ? &delta : nullptr);
                changed |= session == view_;
            }
    }
    if (changed) {
        QScopedValueRollback<bool> changing(updatingSelection_, true);
        const auto id = selected_ ? selected_->id : 0;
        model_->refreshApplications(delta);
        if (view_ == 0 && follow_->isChecked())
            table_->scrollToBottom();
        if (id) {
            const auto row = model_->rowForId(id);
            if (row >= 0)
                table_->setCurrentIndex(model_->index(row, 0));
        }
        showDetails();
        if (selectedDetails_ && !detailsPending_) {
            const auto before = selectedDetails_->fields.size();
            appendDnsFields();
            if (selectedDetails_->fields.size() > before) {
                fieldItems_.push_back({nullptr, &selectedDetails_->fields.back()});
                detailsPending_ = true;
                detailTimer_.start(0);
            }
        }
        updateStatus();
    }
    const auto diagnostics = applicationIndex_[view_].diagnostics();
    analysisPending_->setText(QString::number(diagnostics.count(AnalysisStatus::Pending)));
    analysisIncomplete_->setText(QString::number(diagnostics.incomplete()));
    for (unsigned i = 0; i < analysisStates_.size(); ++i)
        analysisStates_[i]->setText(QString::number(diagnostics.states[i + 1]));
    refreshAnalysisSources();
    tryClose();
}
bool MainWindow::applyExpression(const QString &text) {
    const auto source = text.trimmed();
    std::shared_ptr<const DisplayExpression> expression;
    if (!source.isEmpty()) {
        const auto parsed = compileDisplayFilter(source.toStdString());
        if (!parsed.value) {
            expressionError_->setText(QString::number(parsed.position + 1) + ": " +
                                      i18n::text(q(parsed.error)));
            expressionError_->show();
            style::setFlag(expressionInput_, "invalid", true);
            return false;
        }
        expression = parsed.value;
    }
    expressionError_->hide();
    style::setFlag(expressionInput_, "invalid", false);
    rememberFilter(model_->filter(), source);
    const auto selectedId = selected_ ? selected_->id : 0;
    {
        QScopedValueRollback<bool> changing(updatingSelection_, true);
        model_->setExpression(std::move(expression));
        const auto row = selectedId ? model_->rowForId(selectedId) : -1;
        if (model_->rowCount()) table_->setCurrentIndex(model_->index(row >= 0 ? row : 0, 0));
    }
    expressionInput_->setText(source);
    expressionChip_->setCondition(source);
    showDetails();
    updateStatus();
    return true;
}
void MainWindow::setTlsKeyLog(const QString &path) {
    if (!path.isEmpty())
        keyDirectory_ = QFileInfo(path).absolutePath();
    for (int session = 0; session < 2; ++session) {
        resetApplications(session);
        applications_[session]->setKeyLog(path);
        submitApplications(session);
    }
    model_->refreshApplications();
}
void MainWindow::showApplicationAnalysis() {
    if (!selected_ || closing_) return;
    if (!applicationDock_) {
        applicationDock_ = createAnalysisDock("应用分析", "applicationAnalysisDock");
        applicationView_ = new ApplicationView(applicationDock_);
        applicationDock_->setContent(applicationView_);
        connect(applicationDock_, &AnalysisDock::rebindRequested, this, &MainWindow::bindApplicationSource);
        connect(applicationView_, &ApplicationView::filterRequested, this,
                [this](const QString &predicate, bool unique, SourceContext context) {
                    if (context.session == view_ && sourceValid(context, true)) applyQuickFilter(predicate, unique);
                    else applicationDock_->showError("筛选来源已失效");
                });
        connect(applicationView_, &ApplicationView::analysisHelpRequested, this, &MainWindow::showAnalysisHelp);
        connect(applicationView_, &ApplicationView::locateRequested, this, [this](quint64 id) {
            if (closing_) return;
            if (!sourceValid(applicationContext_, true) || applicationContext_.session != view_) {
                applicationDock_->showError("分析来源已变化，请切回来源或重新分析");
                return;
            }
            const auto row = model_->rowForId(id);
            if (row < 0) {
                applicationDock_->showError(storeFor(view_).find(id) ? "报文已被筛选" : "报文已覆盖");
                return;
            }
            applicationDock_->showError({});
            follow_->setChecked(false);
            selectPacket(row);
            table_->scrollTo(model_->index(row, 0));
            raise();
            activateWindow();
        });
    }
    bindApplicationSource();
    presentAnalysisDock(applicationDock_);
}
void MainWindow::bindApplicationSource() {
    if (!selected_) {
        applicationDock_->showError("选择数据包后可进行应用分析");
        return;
    }
    applicationContext_ = sourceContext(view_);
    applicationSourceName_ = sourceNames_[view_];
    applicationPacket_ = selected_->id;
    applicationView_->setBinding(applicationContext_, ApplicationView::Scope::Packet, applicationPacket_, true);
    applicationInvalidated_ = false;
    applicationDock_->showError({});
    applicationView_->setResults({});
    refreshAnalysisSources();
}
void MainWindow::appendDnsFields() {
    if (!selected_ || !selectedDetails_ ||
        std::any_of(selectedDetails_->fields.begin(), selectedDetails_->fields.end(),
                    [](const auto &f) { return f.name == "DNS"; }))
        return;
    auto details = std::make_shared<PacketDetails>(*selectedDetails_);
    Field dns{"DNS", "", 0, 0, {}};
    auto nodes = [](auto &&self, const std::vector<Field> &fields) -> std::size_t {
        std::size_t count = fields.size();
        for (const auto &field : fields)
            count += self(self, field.children);
        return count;
    };
    const auto existing = nodes(nodes, details->fields);
    if (existing >= maxPacketFields - 1)
        return;
    const auto results = applicationIndex_[view_].results(selected_->id);
    for (const auto &result : results)
        for (const auto &message : result->messages)
            if (message.protocol == "DNS" && message.source == DataSource::Original) {
                dns.offset = message.offset;
                dns.length = message.length;
                for (const auto &field : message.fields)
                    if (dns.children.size() < maxPacketFields - existing - 1)
                        dns.children.push_back({field.name,
                                                applicationText(field.value),
                                                field.offset,
                                                field.length,
                                                {}, field.key});
            }
    if (dns.children.empty())
        return;
    details->fields.push_back(std::move(dns));
    details->estimatedBytes += details->fields.back().children.size() * sizeof(Field);
    selectedDetails_ = std::move(details);
}
void MainWindow::configureRecording() {
    if (recordingBusy() || busy())
        return;
    auto *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle("Recording settings");
    auto *form = new QFormLayout(dialog);
    auto *directory = new QLineEdit(recordingOptions_.directory, dialog);
    directory->setObjectName("recordingDirectory");
    form->addRow("Directory", directory);
    auto *browse = new QPushButton("Browse", dialog);
    form->addRow(browse);
    connect(browse, &QPushButton::clicked, dialog, [dialog, directory] {
        const auto path = QFileDialog::getExistingDirectory(
            dialog, i18n::text("Directory"), directory->text(), QFileDialog::DontUseNativeDialog);
        if (!path.isEmpty())
            directory->setText(path);
    });
    auto *size = new QSpinBox(dialog);
    size->setRange(1, 4096);
    size->setValue(static_cast<int>(recordingOptions_.fileBytes / 1048576));
    form->addRow("File MiB", size);
    auto *seconds = new QSpinBox(dialog);
    seconds->setRange(1, 86400);
    seconds->setValue(static_cast<int>(recordingOptions_.durationMs / 1000));
    form->addRow("Seconds", seconds);
    auto *disk = new QSpinBox(dialog);
    disk->setRange(2, 1048576);
    disk->setValue(static_cast<int>(recordingOptions_.diskBytes / 1048576));
    form->addRow("Disk MiB", disk);
    auto *error = new QLabel(dialog);
    form->addRow(error);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, dialog);
    form->addRow(buttons);
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, dialog,
            [this, dialog, directory, size, seconds, disk, error] {
                if (directory->text().isEmpty() || disk->value() < 2 * size->value()) {
                    i18n::setLabel(error, "Disk budget must fit two files");
                    return;
                }
                recordingOptions_.directory = QDir(directory->text()).absolutePath();
                recordingOptions_.fileBytes = std::uint64_t(size->value()) * 1048576;
                recordingOptions_.diskBytes = std::uint64_t(disk->value()) * 1048576;
                recordingOptions_.durationMs = std::uint64_t(seconds->value()) * 1000;
                dialog->accept();
            });
    i18n::bind(dialog);
    dialog->show();
}
} // namespace etherscope
