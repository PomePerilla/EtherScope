#include "ui/main_window.h"
#include "ui/filter_chip.h"
#include "ui/helpers.h"
#include "ui/language.h"
#include "ui/style.h"
#include "ui/application_view.h"
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
#include <QSpinBox>
#include <QTableView>
#include <QVBoxLayout>
#include <algorithm>
#include <set>

namespace etherscope {
void MainWindow::initializeAnalysis(const MainWindowOptions& options) {
    for(unsigned i=0;i<2;++i){applications_[i]=std::make_unique<ApplicationAnalysisService>(this,options.application);connect(applications_[i].get(),&ApplicationAnalysisService::changed,this,&MainWindow::tryClose,Qt::QueuedConnection);connect(applications_[i].get(),&ApplicationAnalysisService::keyLogChanged,this,[this](bool success,const QString& error){if(!success)reportError(error);},Qt::QueuedConnection);}
    model_->setApplicationIndex(&applicationIndex_[view_]);
    connect(&applicationTimer_,&QTimer::timeout,this,&MainWindow::collectApplications);applicationTimer_.start(100);
    connect(expressionInput_,&QLineEdit::returnPressed,this,[this]{applyExpression(expressionInput_->text());});
    connect(expressionChip_,&QPushButton::clicked,this,[this]{expressionInput_->clear();applyExpression({});});
    connect(&recording_,&RecordingService::finished,this,[this](quint64 request,bool success,const QString& error){if(request!=recording_.generation())return;if(!success){closing_=false;reportError(error);}updateButtons();updateStatus();tryClose();},Qt::QueuedConnection);
}
void MainWindow::resetApplications(int session){applications_[session]->reset();applicationIndex_[session].clear();applicationSubmitted_[session]=0;}
void MainWindow::submitApplications(int session) {
    auto& store=session==0?live_:file_;std::vector<std::shared_ptr<const Packet>> packets;std::set<std::uint64_t> dirty;
    for(const auto& p:store.packets())if(p->id>applicationSubmitted_[session]){packets.push_back(p);if(p->tcpConversationId)dirty.insert(p->tcpConversationId);}
    std::vector<TcpConversation> conversations;for(auto id:dirty)if(const auto* c=store.tcp().find(id))conversations.push_back(*c);
    if(!packets.empty())applicationSubmitted_[session]=packets.back()->id;
    applications_[session]->submit(std::move(packets),std::move(conversations),store.packets().empty()?0:store.packets().front()->id);
    applicationIndex_[session].prune(store.packets().empty()?0:store.packets().front()->id,store.packets().empty()?0:store.packets().back()->id);
}
void MainWindow::collectApplications() {
    bool changed=false;
    for(int session=0;session<2;++session) {
        const auto& store=session==0?live_:file_;auto updates=applications_[session]->takeResults();
        for(auto& update:updates)if(update.generation==applications_[session]->generation()) {
            const auto first=store.packets().empty()?0:store.packets().front()->id,last=store.packets().empty()?0:store.packets().back()->id;
            std::erase_if(update.facts,[&](const auto& pair){return !first || pair.first<first || pair.first>last;});
            applicationIndex_[session].apply(update.conversation,std::move(update.result),std::move(update.facts));changed|=session==view_;
        }
    }
    if(changed){const auto id=selected_?selected_->id:0;model_->refreshApplications();if(id){const auto row=model_->rowForId(id);if(row>=0)table_->setCurrentIndex(model_->index(row,0));}showDetails();if(selectedDetails_ && !detailsPending_){const auto before=selectedDetails_->fields.size();appendDnsFields();if(selectedDetails_->fields.size()>before){fieldItems_.push_back({nullptr,&selectedDetails_->fields.back()});detailsPending_=true;detailTimer_.start(0);}}updateStatus();}
    std::size_t pending=0,incomplete=0;for(const auto& p:currentStore().packets())if((p->tcp && p->tcp->payloadLength) || (p->udp && (p->udp->sourcePort==53 || p->udp->destinationPort==53))){const auto* facts=applicationIndex_[view_].facts(p->id);if(!facts || facts->status==AnalysisStatus::Pending)++pending;else if(facts->status!=AnalysisStatus::Complete)++incomplete;}
    analysisPending_->setText(QString::number(pending));analysisIncomplete_->setText(QString::number(incomplete));tryClose();
}
bool MainWindow::applyExpression(const QString& text) {
    const auto source=text.trimmed();std::shared_ptr<const DisplayExpression> expression;
    if(!source.isEmpty()){const auto parsed=compileDisplayFilter(source.toStdString());if(!parsed.value){expressionError_->setText(QString::number(parsed.position+1)+": "+i18n::text(q(parsed.error)));expressionError_->show();style::setFlag(expressionInput_,"invalid",true);return false;}expression=parsed.value;}
    expressionError_->hide();style::setFlag(expressionInput_,"invalid",false);model_->setExpression(std::move(expression));expressionChip_->setCondition(source);showDetails();updateStatus();return true;
}
void MainWindow::setTlsKeyLog(const QString& path){if(!path.isEmpty())keyDirectory_=QFileInfo(path).absolutePath();for(int session=0;session<2;++session){resetApplications(session);applications_[session]->setKeyLog(path);submitApplications(session);}model_->refreshApplications();}
void MainWindow::showApplicationAnalysis() {
    if(!selected_)return;auto* dialog=new QDialog(this);dialog->setAttribute(Qt::WA_DeleteOnClose);dialog->setWindowTitle("Application analysis");dialog->resize(1000,650);auto* layout=new QVBoxLayout(dialog);auto* view=new ApplicationView(dialog);
    view->setResults(applicationIndex_[view_].results(selected_->id));layout->addWidget(view);
    connect(view,&ApplicationView::locateRequested,this,[this](quint64 id){const auto row=model_->rowForId(id);if(row<0){reportError("Packet is no longer visible");return;}selectPacket(row);table_->scrollTo(model_->index(row,0));});i18n::bind(dialog);dialog->show();
}
void MainWindow::appendDnsFields() {
    if(!selected_ || !selectedDetails_ || std::any_of(selectedDetails_->fields.begin(),selectedDetails_->fields.end(),[](const auto& f){return f.name=="DNS";}))return;
    auto details=std::make_shared<PacketDetails>(*selectedDetails_);Field dns{"DNS","",0,0,{}};
    auto nodes=[](auto&& self,const std::vector<Field>& fields)->std::size_t{std::size_t count=fields.size();for(const auto& field:fields)count+=self(self,field.children);return count;};const auto existing=nodes(nodes,details->fields);if(existing>=maxPacketFields-1)return;
    const auto results=applicationIndex_[view_].results(selected_->id);
    for(const auto& result:results)for(const auto& message:result->messages)if(message.protocol=="DNS" && message.source==DataSource::Original) {
        dns.offset=message.offset;dns.length=message.length;
        for(const auto& field:message.fields)if(dns.children.size()<maxPacketFields-existing-1)dns.children.push_back({field.name,applicationText(field.value),field.offset,field.length,{}});
    }
    if(dns.children.empty())return;details->fields.push_back(std::move(dns));details->estimatedBytes+=details->fields.back().children.size()*sizeof(Field);selectedDetails_=std::move(details);
}
void MainWindow::configureRecording() {
    if(recording_.running() || busy())return;
    auto* dialog=new QDialog(this);dialog->setAttribute(Qt::WA_DeleteOnClose);dialog->setWindowTitle("Recording settings");auto* form=new QFormLayout(dialog);auto* directory=new QLineEdit(recordingOptions_.directory,dialog);directory->setObjectName("recordingDirectory");form->addRow("Directory",directory);
    auto* browse=new QPushButton("Browse",dialog);form->addRow(browse);connect(browse,&QPushButton::clicked,dialog,[dialog,directory]{const auto path=QFileDialog::getExistingDirectory(dialog,i18n::text("Directory"),directory->text(),QFileDialog::DontUseNativeDialog);if(!path.isEmpty())directory->setText(path);});
    auto* size=new QSpinBox(dialog);size->setRange(1,4096);size->setValue(static_cast<int>(recordingOptions_.fileBytes/1048576));form->addRow("File MiB",size);
    auto* seconds=new QSpinBox(dialog);seconds->setRange(1,86400);seconds->setValue(static_cast<int>(recordingOptions_.durationMs/1000));form->addRow("Seconds",seconds);
    auto* disk=new QSpinBox(dialog);disk->setRange(2,1048576);disk->setValue(static_cast<int>(recordingOptions_.diskBytes/1048576));form->addRow("Disk MiB",disk);auto* error=new QLabel(dialog);form->addRow(error);
    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel,dialog);form->addRow(buttons);connect(buttons,&QDialogButtonBox::rejected,dialog,&QDialog::reject);
    connect(buttons,&QDialogButtonBox::accepted,dialog,[this,dialog,directory,size,seconds,disk,error]{if(directory->text().isEmpty() || disk->value()<2*size->value()){i18n::setLabel(error,"Disk budget must fit two files");return;}recordingOptions_.directory=QDir(directory->text()).absolutePath();recordingOptions_.fileBytes=std::uint64_t(size->value())*1048576;recordingOptions_.diskBytes=std::uint64_t(disk->value())*1048576;recordingOptions_.durationMs=std::uint64_t(seconds->value())*1000;dialog->accept();});i18n::bind(dialog);dialog->show();
}
}
