#include "ui/application_view.h"
#include "ui/language.h"
#include <QComboBox>
#include <QElapsedTimer>
#include <QFontDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTextBlock>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace etherscope {
ApplicationView::ApplicationView(QWidget* parent):QWidget(parent) {
    auto* layout=new QVBoxLayout(this);layout->setContentsMargins(0,0,0,0);auto* bar=new QHBoxLayout;
    sources_=new QComboBox(this);sources_->setObjectName("applicationDataSource");sources_->addItems({"All sources","Original","Reassembled","Decrypted"});bar->addWidget(sources_);packets_=new QComboBox(this);packets_->setObjectName("applicationPackets");bar->addWidget(packets_,1);auto* locate=new QPushButton("定位",this);bar->addWidget(locate);layout->addLayout(bar);
    auto* splitter=new QSplitter(Qt::Vertical,this);list_=new QTreeWidget(splitter);list_->setObjectName("applicationMessages");list_->setHeaderLabels({"协议","方向","摘要","状态"});list_->setUniformRowHeights(true);list_->setColumnWidth(0,75);list_->setColumnWidth(1,60);list_->setColumnWidth(2,350);
    auto* lower=new QSplitter(Qt::Horizontal,splitter);fields_=new QTreeWidget(lower);fields_->setObjectName("applicationFields");fields_->setHeaderLabels({"字段","值"});fields_->setUniformRowHeights(true);fields_->setColumnWidth(0,180);bytes_=new QPlainTextEdit(lower);bytes_->setObjectName("applicationBytes");bytes_->setReadOnly(true);bytes_->setLineWrapMode(QPlainTextEdit::NoWrap);bytes_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));layout->addWidget(splitter,1);
    auto* pager=new QHBoxLayout;auto* previous=new QPushButton("上一页",this);auto* next=new QPushButton("下一页",this);page_=new QLabel(this);pager->addWidget(previous);pager->addWidget(page_,1);pager->addWidget(next);layout->addLayout(pager);
    connect(previous,&QPushButton::clicked,this,[this]{page(offset_>=4096?offset_-4096:0);});connect(next,&QPushButton::clicked,this,[this]{page(offset_+4096);});
    connect(list_,&QTreeWidget::currentItemChanged,this,[this]{select();});connect(sources_,&QComboBox::currentIndexChanged,this,[this]{setResults(results_);});
    connect(locate,&QPushButton::clicked,this,[this]{if(packets_->currentIndex()>=0)emit locateRequested(packets_->currentData().toULongLong());});
    connect(fields_,&QTreeWidget::currentItemChanged,this,[this](QTreeWidgetItem* item){if(!item || !selected_)return;const auto offset=item->data(0,Qt::UserRole).toULongLong();page(static_cast<std::size_t>(offset/4096*4096));});
    connect(&fillTimer_,&QTimer::timeout,this,&ApplicationView::fill);fillTimer_.setInterval(0);i18n::bind(this);
    connect(&i18n::language(),&i18n::Language::changed,this,[this]{setResults(results_);});
}
void ApplicationView::setResults(std::vector<std::shared_ptr<const ApplicationResult>> results) {
    fillTimer_.stop();selected_=nullptr;results_=std::move(results);messages_.clear();list_->clear();fields_->clear();bytes_->clear();packets_->clear();filled_=fieldFilled_=0;
    for(const auto& r:results_)for(const auto& message:r->messages)if(!sources_->currentIndex() || sources_->currentIndex()==int(message.source)+1)messages_.push_back(&message);
    fillTimer_.start();
}
void ApplicationView::fill() {
    QElapsedTimer elapsed;elapsed.start();
    while(filled_<messages_.size() && elapsed.nsecsElapsed()<2000000){const auto* m=messages_[filled_];auto* item=new QTreeWidgetItem(list_);item->setText(0,QString::fromStdString(m->protocol));item->setText(1,m->direction?"B -> A":"A -> B");item->setText(2,QString::fromStdString(m->summary));item->setToolTip(2,item->text(2));item->setText(3,m->status==AnalysisStatus::Complete?QString{}:i18n::text("Incomplete"));item->setData(0,Qt::UserRole,qulonglong(filled_++));}
    while(selected_ && fieldFilled_<selected_->fields.size() && elapsed.nsecsElapsed()<2000000){const auto& field=selected_->fields[fieldFilled_++];auto* item=new QTreeWidgetItem(fields_);item->setText(0,i18n::text(QString::fromStdString(field.name)));item->setText(1,QString::fromStdString(applicationText(field.value)));item->setToolTip(1,item->text(1));item->setData(0,Qt::UserRole,qulonglong(field.offset));}
    if(filled_==messages_.size() && (!selected_ || fieldFilled_==selected_->fields.size()))fillTimer_.stop();
    if(!selected_ && list_->topLevelItemCount())list_->setCurrentItem(list_->topLevelItem(0));
}
void ApplicationView::select() {
    auto* item=list_->currentItem();selected_=item && item->data(0,Qt::UserRole).toULongLong()<messages_.size()?messages_[item->data(0,Qt::UserRole).toULongLong()]:nullptr;fields_->clear();packets_->clear();fieldFilled_=0;
    if(selected_)for(const auto& source:selected_->sources)if(packets_->findData(QVariant::fromValue<qulonglong>(source.packetId))<0)packets_->addItem(QString::number(source.packetId),QVariant::fromValue<qulonglong>(source.packetId));
    page(selected_?selected_->offset/4096*4096:0);fillTimer_.start();
}
void ApplicationView::page(std::size_t offset) {
    if(!selected_ || !selected_->bytes){bytes_->clear();page_->clear();return;}const auto& content=*selected_->bytes;offset_=content.empty()?0:std::min(offset/4096,(content.size()-1)/4096)*4096;const auto end=std::min(content.size(),offset_+4096);QString text;
    for(auto at=offset_;at<end;at+=16){text+=QString("%1  ").arg(qulonglong(at),6,16,QChar('0'));for(unsigned j=0;j<16;++j)text+=at+j<end?QString("%1 ").arg(content[at+j],2,16,QChar('0')):"   ";text+="  ";for(unsigned j=0;j<16 && at+j<end;++j){const auto c=content[at+j];text+=c>=32 && c<127?QChar(c):QChar('.');}text+='\n';}
    bytes_->setPlainText(text);page_->setText(QString("%1-%2 / %3").arg(qulonglong(offset_)).arg(qulonglong(end?end-1:0)).arg(qulonglong(content.size())));
}
}
