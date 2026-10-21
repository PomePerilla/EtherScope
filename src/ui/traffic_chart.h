#pragma once
#include <QWidget>
#include <deque>
#include <map>
#include <string>

namespace etherscope {
class TrafficChart final:public QWidget {
public:
    explicit TrafficChart(QWidget* parent=nullptr);
    void addSample(double pps,double bytes);
    void setProtocols(const std::map<std::string,std::uint64_t>& counts);
    void reset();
protected:
    void paintEvent(QPaintEvent*) override;
private:
    struct Sample { double pps{},bytes{}; };
    std::deque<Sample> samples_;
    std::map<std::string,std::uint64_t> protocols_;
};
}
