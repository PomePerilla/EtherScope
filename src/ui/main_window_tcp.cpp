#include "ui/main_window.h"
#include "ui/tcp_dialog.h"
#include <QCheckBox>
#include <QComboBox>
#include <QSignalBlocker>
#include <QTableView>
#include <algorithm>

namespace etherscope {
void MainWindow::refreshTcpConversations() {if(tcpDialog_)tcpDialog_->refresh(currentStore(),view_==0?"实时":"文件");}
void MainWindow::showTcpConversations() {
    if(closing_)return;
    if(!tcpDialog_) {
        tcpDialog_=new TcpDialog(this);
        connect(tcpDialog_,&TcpDialog::filterRequested,this,[this](quint64 id,quint64 generation,const SessionStore* store){
            if(closing_ || store!=&currentStore() || generation!=store->tcp().generation() || !store->tcp().find(id))return;
            auto filter=model_->filter();filter.protocol="TCP";filter.icmpType.reset();filter.tcpConversationId=id;
            if(std::none_of(store->packets().begin(),store->packets().end(),[&](const auto& packet){return filter.matches(*packet);})) {
                tcpDialog_->showError("无匹配报文");return;
            }
            {QSignalBlocker block(protocol_);protocol_->setCurrentText("TCP");}commitFilter(std::move(filter));follow_->setChecked(false);tcpDialog_->close();
        });
        connect(tcpDialog_,&TcpDialog::locateRequested,this,[this](quint64 id,quint64 generation,const SessionStore* store){
            if(closing_ || store!=&currentStore() || generation!=store->tcp().generation())return;
            const auto row=model_->rowForId(id);
            if(row<0){const bool retained=std::any_of(store->packets().begin(),store->packets().end(),[id](const auto& packet){return packet->id==id;});tcpDialog_->showError(retained?"报文已被筛选":"报文已覆盖");return;}
            actionError_.clear();follow_->setChecked(false);selectPacket(row);table_->scrollTo(model_->index(row,0));tcpDialog_->close();raise();activateWindow();
        });
    }
    refreshTcpConversations();if(selected_ && selected_->tcpConversationId)tcpDialog_->selectConversation(selected_->tcpConversationId);
    tcpDialog_->show();tcpDialog_->raise();tcpDialog_->activateWindow();
}
}
