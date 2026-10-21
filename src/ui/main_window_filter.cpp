#include "ui/main_window.h"
#include "ui/filter_chip.h"
#include "ui/helpers.h"
#include "ui/style.h"
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QScopedValueRollback>
#include <QSignalBlocker>
#include <QTableView>

namespace etherscope {
void MainWindow::applyFilter() {
    const auto macDirection=static_cast<Direction>(macDirection_->currentIndex()),ipDirection=static_cast<Direction>(ipDirection_->currentIndex());
    const auto macResult=parseFilter(mac_->text().toStdString(),macDirection,"",Direction::Either);
    const auto ipResult=parseFilter("",Direction::Either,ip_->text().toStdString(),ipDirection);
    macError_->setText(q(macResult.error));macError_->setVisible(!macResult.value);style::setFlag(mac_,"invalid",!macResult.value);
    ipError_->setText(q(ipResult.error));ipError_->setVisible(!ipResult.value);style::setFlag(ip_,"invalid",!ipResult.value);
    if(!macResult.value || !ipResult.value)return;
    auto filter=*macResult.value;filter.ip=ipResult.value->ip;filter.ipv6=ipResult.value->ipv6;filter.ipDirection=ipDirection;filter.protocol=model_->filter().protocol;filter.icmpType=model_->filter().icmpType;filter.tcpConversationId=model_->filter().tcpConversationId;
    commitFilter(std::move(filter));
}
void MainWindow::commitFilter(FilterSpec filter) {
    const auto selectedId=selected_?selected_->id:0;
    {
        QScopedValueRollback<bool> changing(updatingSelection_,true);model_->setFilter(std::move(filter));
        const auto row=selectedId?model_->rowForId(selectedId):-1;
        if(model_->rowCount())table_->setCurrentIndex(model_->index(row>=0?row:0,0));
    }
    updateFilterStatus();showDetails();updateStatus();
}
void MainWindow::updateFilterStatus() {
    const auto& f=model_->filter();
    icmpTypeGroup_->setVisible(f.protocol=="ICMP");
    {QSignalBlocker block(icmpType_);icmpType_->setCurrentIndex(icmpType_->findData(f.icmpType?int(*f.icmpType):-1));}
    icmpChip_->setCondition(f.icmpType?icmpType_->currentText():QString{});
    auto direction=[](Direction value){return value==Direction::Source?QString("源 "):(value==Direction::Destination?QString("目的 "):QString{});};
    macChip_->setCondition(f.mac?direction(f.macDirection)+"MAC "+q(formatMac(*f.mac)):QString{});
    QString ip;if(f.ip)ip="IPv4 "+q(formatIp(*f.ip));else if(f.ipv6)ip="IPv6 "+q(formatIpv6(*f.ipv6));
    ipChip_->setCondition(ip.isEmpty()?QString{}:direction(f.ipDirection)+ip);protocolChip_->setCondition(q(f.protocol));
    conversationChip_->setCondition(f.tcpConversationId?QString("会话 %1").arg(*f.tcpConversationId):QString{});
}
}
