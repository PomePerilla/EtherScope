#include "ui/traffic_chart.h"
#include "ui/language.h"
#include <QPainter>
#include <QPainterPath>
#include <algorithm>

namespace etherscope {
TrafficChart::TrafficChart(QWidget* parent):QWidget(parent) {setMinimumHeight(100);setMaximumHeight(106);}
void TrafficChart::addSample(double pps,double bytes) {samples_.push_back({pps,bytes});if(samples_.size()>120)samples_.pop_front();update();}
void TrafficChart::setProtocols(const std::map<std::string,std::uint64_t>& counts) {protocols_=counts;update();}
void TrafficChart::reset() {samples_.clear();protocols_.clear();update();}
void TrafficChart::paintEvent(QPaintEvent*) {
    QPainter p(this);p.setRenderHint(QPainter::Antialiasing);
    const auto ink=palette().color(QPalette::Text),muted=palette().color(QPalette::PlaceholderText),border=palette().color(QPalette::Mid);
    const bool dark=palette().color(QPalette::Base).lightness()<128;
    const QColor amber(dark?"#cca700":"#886500"),teal(dark?"#4ec9b0":"#167b69");
    const int third=width()/3,pad=12;
    p.setPen(border);p.drawLine(third,0,third,height());p.drawLine(2*third,0,2*third,height());
    auto graph=[&](int left,bool bytes) {
        const double latest=samples_.empty()?0:(bytes?samples_.back().bytes:samples_.back().pps);
        p.setPen(muted);p.drawText(left+pad,17,i18n::text(bytes?"流量":"包速率"));
        auto number=p.font();number.setFamily("Consolas");number.setPixelSize(18);p.setFont(number);p.setPen(bytes?teal:amber);
        p.drawText(left+pad,40,QString::number(bytes?latest/1024:latest,'f',bytes?1:0));
        auto small=font();small.setPixelSize(11);p.setFont(small);p.setPen(muted);
        p.drawText(QRect(left+pad,24,third-2*pad,18),Qt::AlignRight|Qt::AlignVCenter,bytes?"KiB/s":"pps");
        QRectF area(left+pad,49,std::max(10,third-2*pad),height()-59);
        p.setPen(QPen(border,1,Qt::DotLine));p.drawLine(area.bottomLeft(),area.bottomRight());
        p.drawLine(QPointF(area.left(),area.center().y()),QPointF(area.right(),area.center().y()));
        double peak=1;for(const auto& sample:samples_)peak=std::max(peak,bytes?sample.bytes:sample.pps);
        QPainterPath line;
        for(std::size_t i=0;i<samples_.size();++i) {
            const auto& sample=samples_[i];const QPointF point(area.left()+area.width()*i/119.0,area.bottom()-area.height()*(bytes?sample.bytes:sample.pps)/peak);
            if(i==0)line.moveTo(point);else line.lineTo(point);
        }
        p.setPen(QPen(bytes?teal:amber,1.3));p.drawPath(line);
    };
    graph(0,false);graph(third,true);
    p.setFont(font());p.setPen(muted);p.drawText(2*third+pad,17,i18n::text("协议"));
    std::uint64_t total=0;for(const auto& [_,count]:protocols_)total+=count;
    const int columns=protocols_.size()>4?2:1,columnWidth=(width()-2*third-2*pad)/columns;
    std::size_t index=0;const int rows=(static_cast<int>(protocols_.size())+columns-1)/columns;
    for(const auto& [name,count]:protocols_) {
        const int column=static_cast<int>(index)/std::max(1,rows),row=static_cast<int>(index)%std::max(1,rows);
        const int x=2*third+pad+column*columnWidth,y=35+row*16;++index;
        if(y>height()-7)break;
        const int span=columnWidth-12;p.setPen(ink);p.drawText(x,y,i18n::text(QString::fromStdString(name)));
        p.setPen(amber);p.drawText(QRect(x,y-12,span,15),Qt::AlignRight|Qt::AlignVCenter,QString::number(count));
        const double ratio=total?double(count)/double(total):0;
        p.fillRect(QRectF(x,y+3,std::max(1.0,span*ratio),1),teal);
    }
}
}
