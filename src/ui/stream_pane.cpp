#include "ui/stream_pane.h"
#include "ui/style.h"
#include "ui/language.h"
#include <QAbstractTableModel>
#include <QComboBox>
#include <QFontDatabase>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTableView>
#include <QTabWidget>
#include <QVBoxLayout>
#include <algorithm>

namespace etherscope {
namespace {
QString markText(StreamEventKind kind) {
    switch(kind) {
        case StreamEventKind::Duplicate:return i18n::text("重复数据");
        case StreamEventKind::Overlap:return i18n::text("重叠数据");
        case StreamEventKind::GapAhead:return i18n::text("顺序缺口");
        case StreamEventKind::GapFilled:return i18n::text("后到补齐");
        case StreamEventKind::Conflict:return i18n::text("数据冲突");
    }
    return "-";
}
}
class StreamTableModel final:public QAbstractTableModel {
public:
    StreamTableModel(bool events,QObject* parent):QAbstractTableModel(parent),events_(events) {connect(&i18n::language(),&i18n::Language::changed,this,[this]{emit headerDataChanged(Qt::Horizontal,0,columnCount()-1);if(rowCount())emit dataChanged(index(0,0),index(rowCount()-1,columnCount()-1));});}
    int rowCount(const QModelIndex& parent={}) const override {return parent.isValid() || !result_?0:static_cast<int>(events_?result_->events.size():result_->directions[direction_].blocks.size());}
    int columnCount(const QModelIndex& parent={}) const override {return parent.isValid()?0:(events_?6:4);}
    QVariant data(const QModelIndex& index,int role) const override {
        if(!result_ || !index.isValid() || index.row()<0 || index.row()>=rowCount() || index.column()<0 || index.column()>=columnCount())return {};
        const auto number=[](std::uint64_t n){return QVariant::fromValue<qulonglong>(n);};
        if(role==Qt::FontRole)return QFontDatabase::systemFont(QFontDatabase::FixedFont);
        if(events_) {
            const auto& event=result_->events[index.row()];
            if(role==Qt::UserRole)return number(index.column()==5?event.relatedPacketId:event.packetId);
            if(role!=Qt::DisplayRole && role!=Qt::ToolTipRole)return {};
            switch(index.column()){case 0:return number(event.packetId);case 1:return event.direction==0?"A -> B":"B -> A";case 2:return markText(event.kind);case 3:return number(event.sequence);case 4:return number(event.length);case 5:return event.relatedPacketId?number(event.relatedPacketId):QVariant("-");}
        } else {
            const auto& block=result_->directions[direction_].blocks[index.row()];
            if(role==Qt::UserRole)return number(block.packetId);
            if(role!=Qt::DisplayRole && role!=Qt::ToolTipRole)return {};
            switch(index.column()){case 0:return number(block.sequence);case 1:return number(block.length);case 2:return block.packetId?number(block.packetId):QVariant("-");case 3:return i18n::text(block.bytes.empty()?"缺口":"数据");}
        }
        return {};
    }
    QVariant headerData(int section,Qt::Orientation orientation,int role) const override {
        static const QStringList ranges={"SEQ","字节","包号","状态"},events={"包号","方向","标记","SEQ","字节","关联包号"};const auto& titles=events_?events:ranges;
        return orientation==Qt::Horizontal && role==Qt::DisplayRole && section>=0 && section<titles.size()?i18n::text(titles[section]):QVariant{};
    }
    void setResult(std::shared_ptr<const TcpStreamResult> result,unsigned direction){beginResetModel();result_=std::move(result);direction_=direction;endResetModel();}
private:
    bool events_;
    unsigned direction_{};
    std::shared_ptr<const TcpStreamResult> result_;
};
StreamPane::StreamPane(QWidget* parent,StreamDecoder decoder):QWidget(parent),service_(this,std::move(decoder)) {
    setObjectName("streamPane");auto* layout=new QVBoxLayout(this);layout->setContentsMargins(0,0,0,0);layout->setSpacing(style::gap);
    auto* bar=new QHBoxLayout;direction_=new QComboBox(this);direction_->setObjectName("streamDirection");direction_->addItems({"A -> B","B -> A"});bar->addWidget(direction_);
    start_=new QPushButton("重组",this);start_->setObjectName("streamStart");cancel_=new QPushButton("取消",this);cancel_->setObjectName("streamCancel");bar->addWidget(start_);bar->addWidget(cancel_);
    phase_=new QLabel(this);phase_->setObjectName("streamPhase");scope_=new QLabel(this);scope_->setObjectName("streamScope");prefix_=new QLabel(this);prefix_->setObjectName("streamPrefix");limit_=new QLabel(this);limit_->setObjectName("streamLimit");
    for(auto* label:{phase_,scope_,prefix_,limit_})bar->addWidget(label);bar->addStretch();layout->addLayout(bar);
    auto* metrics=new QGridLayout;metrics->setHorizontalSpacing(10);const QStringList titles={"快照包数","重组字节","缺口","重复段","补齐段","冲突字节","占用 KiB","省略标记"};
    for(int i=0;i<8;++i){metrics->addWidget(new QLabel(titles[i],this),i/4,(i%4)*2);metrics_[i]=new QLabel("-",this);metrics_[i]->setObjectName("streamMetric"+QString::number(i));metrics->addWidget(metrics_[i],i/4,(i%4)*2+1);}
    layout->addLayout(metrics);tabs_=new QTabWidget(this);tabs_->setObjectName("streamTabs");layout->addWidget(tabs_,1);
    auto* dataPage=new QWidget(tabs_);auto* dataLayout=new QVBoxLayout(dataPage);dataLayout->setContentsMargins(0,0,0,0);dataLayout->setSpacing(2);
    auto* split=new QSplitter(Qt::Horizontal,dataPage);split->setChildrenCollapsible(false);ranges_=new QTableView(split);ranges_->setObjectName("streamRanges");
    bytes_=new QPlainTextEdit(split);bytes_->setObjectName("streamBytes");bytes_->setReadOnly(true);bytes_->setLineWrapMode(QPlainTextEdit::NoWrap);bytes_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));split->setSizes({340,540});dataLayout->addWidget(split,1);
    auto* pager=new QHBoxLayout;previous_=new QPushButton("上一页",dataPage);previous_->setObjectName("streamPrevious");next_=new QPushButton("下一页",dataPage);next_->setObjectName("streamNext");page_=new QLabel(dataPage);page_->setObjectName("streamPage");locate_=new QPushButton("定位",dataPage);locate_->setObjectName("streamLocate");
    pager->addWidget(previous_);pager->addWidget(next_);pager->addWidget(page_,1);pager->addWidget(locate_);dataLayout->addLayout(pager);tabs_->addTab(dataPage,"字节");
    events_=new QTableView(tabs_);events_->setObjectName("streamEvents");tabs_->addTab(events_,"标记");
    rangeModel_=new StreamTableModel(false,this);eventModel_=new StreamTableModel(true,this);ranges_->setModel(rangeModel_);events_->setModel(eventModel_);
    for(auto* table:{ranges_,events_}){table->setShowGrid(false);table->setAlternatingRowColors(true);table->verticalHeader()->hide();table->verticalHeader()->setDefaultSectionSize(24);table->setSelectionBehavior(QAbstractItemView::SelectRows);table->setSelectionMode(QAbstractItemView::SingleSelection);table->setEditTriggers(QAbstractItemView::NoEditTriggers);table->horizontalHeader()->setStretchLastSection(true);}
    ranges_->setColumnWidth(0,96);ranges_->setColumnWidth(1,74);ranges_->setColumnWidth(2,74);events_->setColumnWidth(0,76);events_->setColumnWidth(1,90);events_->setColumnWidth(2,110);
    connect(start_,&QPushButton::clicked,this,&StreamPane::start);connect(cancel_,&QPushButton::clicked,this,&StreamPane::cancel);
    connect(direction_,&QComboBox::currentIndexChanged,this,[this]{display();});connect(ranges_->selectionModel(),&QItemSelectionModel::currentRowChanged,this,[this]{displayRange();});
    connect(previous_,&QPushButton::clicked,this,[this]{pageStart_=pageStart_>=pageSize_?pageStart_-pageSize_:0;displayPage();});connect(next_,&QPushButton::clicked,this,[this]{pageStart_+=pageSize_;displayPage();});
    connect(locate_,&QPushButton::clicked,this,[this]{if(pagePacketId_)emit locateRequested(pagePacketId_);});
    connect(ranges_,&QTableView::doubleClicked,this,[this](const QModelIndex& index){const auto id=index.data(Qt::UserRole).toULongLong();if(id)emit locateRequested(id);});
    connect(events_,&QTableView::doubleClicked,this,[this](const QModelIndex& index){const auto id=index.data(Qt::UserRole).toULongLong();if(id)emit locateRequested(id);});
    connect(&service_,&StreamService::changed,this,[this]{
        auto result=service_.takeResult();
        if(result && result->request==request_) {
            if(!result->error.isEmpty()){i18n::setLabel(phase_,result->error);emit analysisFinished(request_,false);}
            else if(result->stream && !result->stream->cancelled && result->stream->conversationId==conversation_ && result->stream->generation==generation_){result_=std::move(result->stream);i18n::setLabel(phase_,"已重组");display();emit analysisFinished(request_,true);}
            else {i18n::setLabel(phase_,result->stream && result->stream->cancelled?"已取消":"结果已过期");emit analysisFinished(request_,false);}
        }
        cancel_->setEnabled(service_.busy());emit workChanged();
    },Qt::QueuedConnection);
    clearResult();start_->setEnabled(false);cancel_->setEnabled(false);i18n::bind(this);
}
void StreamPane::setSelection(const SessionStore* store,std::uint64_t id) {
    const auto generation=store?store->tcp().generation():0;if(store_==store && generation_==generation && conversation_==id)return;
    service_.cancel();request_=0;store_=store;generation_=generation;conversation_=id;clearResult();i18n::setLabel(phase_,id?"待重组":"");start_->setEnabled(id!=0);cancel_->setEnabled(service_.busy());
}
void StreamPane::start() {
    if(!store_ || !conversation_ || store_->tcp().generation()!=generation_)return;
    auto snapshot=snapshotTcpStream(*store_,conversation_);if(!snapshot){i18n::setLabel(phase_,"会话已覆盖");return;}
    clearResult();request_=service_.request(std::move(*snapshot));i18n::setLabel(phase_,request_?"分析中":"任务已关闭");cancel_->setEnabled(request_!=0);emit workChanged();
}
void StreamPane::cancel() {service_.cancel();request_=0;clearResult();i18n::setLabel(phase_,"已取消");cancel_->setEnabled(service_.busy());emit workChanged();}
void StreamPane::clearResult() {result_.reset();rangeModel_->setResult({},0);eventModel_->setResult({},0);bytes_->clear();page_->clear();i18n::setLabel(scope_,{});i18n::setLabel(prefix_,{});i18n::setLabel(limit_,{});for(auto* metric:metrics_)metric->setText("-");previous_->setEnabled(false);next_->setEnabled(false);locate_->setEnabled(false);}
void StreamPane::display() {
    const auto direction=static_cast<unsigned>(direction_->currentIndex());rangeModel_->setResult(result_,direction);eventModel_->setResult(result_,direction);if(!result_){displayRange();return;}
    const auto& output=result_->directions[direction];const std::array<QString,8> values={QString::number(result_->inputPackets),QString::number(output.uniqueBytes),QString::number(output.gaps),QString::number(output.duplicateSegments),QString::number(output.gapFilledSegments),QString::number(output.conflictBytes),QString::number(double(result_->estimatedBytes)/1024,'f',1),QString::number(result_->eventsOmitted)};
    for(std::size_t i=0;i<values.size();++i)metrics_[i]->setText(values[i]);i18n::setLabel(scope_,result_->cachePartial?"缓存范围":"");i18n::setLabel(prefix_,output.boundaryConflict?"序号边界":(!output.startKnown?"起点未知":(output.prefixMissing?"起始缺口":(output.suffixMissing?"尾部缺口":""))));i18n::setLabel(limit_,result_->inputLimited || output.limited?"达到上限":"");
    if(rangeModel_->rowCount()){const auto first=std::find_if(output.blocks.begin(),output.blocks.end(),[](const auto& block){return !block.bytes.empty();});ranges_->setCurrentIndex(rangeModel_->index(first==output.blocks.end()?0:static_cast<int>(first-output.blocks.begin()),0));}displayRange();
}
void StreamPane::displayRange(){
    pageStart_=0;const auto row=ranges_->currentIndex().row();
    if(result_ && row>=0){const auto& blocks=result_->directions[static_cast<unsigned>(direction_->currentIndex())].blocks;const auto selected=static_cast<std::size_t>(row);if(selected<blocks.size() && !blocks[selected].bytes.empty()){auto begin=selected;while(begin && !blocks[begin-1].bytes.empty())--begin;for(auto i=begin;i<selected;++i)pageStart_+=blocks[i].bytes.size();pageStart_=pageStart_/pageSize_*pageSize_;}}
    displayPage();
}
void StreamPane::displayPage() {
    bytes_->clear();page_->clear();pagePacketId_=0;previous_->setEnabled(false);next_->setEnabled(false);locate_->setEnabled(false);
    const auto row=ranges_->currentIndex().row();if(!result_ || row<0)return;const auto& blocks=result_->directions[static_cast<unsigned>(direction_->currentIndex())].blocks;if(static_cast<std::size_t>(row)>=blocks.size())return;
    if(blocks[static_cast<std::size_t>(row)].bytes.empty())return;
    auto first=static_cast<std::size_t>(row),last=first+1;
    while(first && !blocks[first-1].bytes.empty())--first;while(last<blocks.size() && !blocks[last].bytes.empty())++last;
    std::size_t total=0;for(auto index=first;index<last;++index)total+=blocks[index].bytes.size();
    pageStart_=std::min(pageStart_/pageSize_,(total-1)/pageSize_)*pageSize_;const auto end=std::min(total,pageStart_+pageSize_);
    std::array<std::uint8_t,pageSize_> pageBytes{};std::size_t position=0;
    for(auto index=first;index<last && position<end;++index) {
        const auto& block=blocks[index];const auto begin=std::max(position,pageStart_),stop=std::min(position+block.bytes.size(),end);
        if(stop>begin){if(!pagePacketId_)pagePacketId_=block.packetId;std::copy(block.bytes.begin()+static_cast<std::ptrdiff_t>(begin-position),block.bytes.begin()+static_cast<std::ptrdiff_t>(stop-position),pageBytes.begin()+static_cast<std::ptrdiff_t>(begin-pageStart_));}position+=block.bytes.size();
    }
    locate_->setEnabled(pagePacketId_!=0);QString text;text.reserve(static_cast<qsizetype>((end-pageStart_)*5));
    for(auto offset=pageStart_;offset<end;offset+=16) {
        text+=QString("%1  ").arg(static_cast<qulonglong>(offset),6,16,QChar('0'));
        for(std::size_t i=0;i<16;++i)text+=offset+i<end?QString("%1 ").arg(pageBytes[offset+i-pageStart_],2,16,QChar('0')):"   ";
        text+="  ";for(auto i=offset;i<std::min(offset+16,end);++i){const auto c=pageBytes[i-pageStart_];text+=c>=32 && c<127?QChar(c):QChar('.');}text+='\n';
    }
    bytes_->setPlainText(text);page_->setText(QString("%1 / %2").arg(pageStart_/pageSize_+1).arg((total+pageSize_-1)/pageSize_));previous_->setEnabled(pageStart_>0);next_->setEnabled(end<total);
}
}
