#pragma once
#include "core/session.h"
#include "core/filter.h"
#include <QAbstractTableModel>
#include <deque>

namespace etherscope {
class PacketModel final:public QAbstractTableModel {
public:
    explicit PacketModel(SessionStore* store,QObject* parent=nullptr);
    int rowCount(const QModelIndex& parent={}) const override;
    int columnCount(const QModelIndex& parent={}) const override;
    QVariant data(const QModelIndex& index,int role=Qt::DisplayRole) const override;
    QVariant headerData(int section,Qt::Orientation orientation,int role) const override;
    void setStore(SessionStore* store);
    void append(std::vector<Packet> packets);
    void clear();
    void setFilter(FilterSpec filter);
    void retranslate();
    std::shared_ptr<const Packet> packetAt(int row) const;
    int rowForId(std::uint64_t id) const;
    const FilterSpec& filter() const { return filter_; }
private:
    SessionStore* store_;
    FilterSpec filter_;
    struct Row {
        std::shared_ptr<const Packet> packet;
        QString time,source,destination,protocol,summary;
        explicit Row(std::shared_ptr<const Packet> value);
    };
    std::deque<Row> visible_;
    void rebuild();
};
}
