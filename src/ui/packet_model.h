#pragma once
#include "core/session.h"
#include "core/filter.h"
#include "core/application_index.h"
#include <QAbstractTableModel>
#include <deque>

namespace etherscope {
struct FindSource;
class PacketModel final : public QAbstractTableModel {
  public:
    explicit PacketModel(SessionStore *store, QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void setStore(SessionStore *store);
    void append(std::vector<Packet> packets);
    void clear();
    void setFilter(FilterSpec filter);
    void retranslate();
    void setApplicationIndex(const ApplicationIndex *index);
    void setExpression(std::shared_ptr<const DisplayExpression> expression);
    const std::shared_ptr<const DisplayExpression> &expression() const {
        return expression_;
    }
    bool matches(const Packet &packet) const;
    void refreshApplications();
    void refreshApplications(const IndexDelta &changes);
    std::uint64_t evaluations() const {
        return evaluations_;
    }
    std::shared_ptr<const Packet> packetAt(int row) const;
    int rowForId(std::uint64_t id) const;
    FindSource findSource(const QList<int> &columns) const;
    const FilterSpec &filter() const {
        return filter_;
    }

  private:
    SessionStore *store_;
    FilterSpec filter_;
    const ApplicationIndex *applications_{};
    std::shared_ptr<const DisplayExpression> expression_;
    struct Row {
        std::shared_ptr<const Packet> packet;
        QString time, source, destination, protocol, summary;
        explicit Row(std::shared_ptr<const Packet> value);
    };
    std::deque<Row> visible_;
    mutable std::uint64_t evaluations_{};
    void rebuild();
};
} // namespace etherscope
