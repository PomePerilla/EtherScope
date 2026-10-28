#include "ui/packet_model.h"
#include <QColor>
#include <QDateTime>
#include <QFontDatabase>
#include <QPainter>
#include <QIcon>
#include <QGuiApplication>
#include "ui/style.h"
#include "ui/icons.h"
#include "ui/language.h"
#include "ui/find_bar.h"
#include <algorithm>

namespace etherscope {
FindSource PacketModel::findSource(const QList<int> &columns) const {
    struct TextRow { QString key; QStringList cells; };
    // Cache strings are implicitly shared; the snapshot never pins raw packet buffers.
    auto rows = std::make_shared<std::vector<TextRow>>();
    rows->reserve(visible_.size());
    for (const auto &row : visible_) {
        const auto &p = *row.packet;
        rows->push_back({QString::number(p.id), {QString::number(p.id), row.time, row.source,
            row.destination, row.protocol, QString::number(p.raw.bytes.size()),
            !p.error.empty() ? i18n::text("异常") : (p.warnings.empty() ? QString{} : i18n::text("提示")), row.summary}});
    }
    return {int(rows->size()), [rows, columns](int index) {
        const auto &row = (*rows)[std::size_t(index)]; QStringList text;
        for (int column : columns) text.append(row.cells[column]);
        return FindDocument{row.key, text.join('\t'), {}};
    }, {}};
}
PacketModel::Row::Row(std::shared_ptr<const Packet> value)
    : packet(std::move(value)),
      time(packet->raw.timestampValid
               ? QDateTime::fromMSecsSinceEpoch(packet->raw.timestampNs / 1000000)
                     .toString("HH:mm:ss.zzz")
               : QString("-")),
      source(packet->source.empty() ? QString("-") : QString::fromStdString(packet->source)),
      destination(packet->destination.empty() ? QString("-")
                                              : QString::fromStdString(packet->destination)),
      protocol(i18n::text(QString::fromStdString(packet->protocol))),
      summary(i18n::text(QString::fromStdString(packet->summary).replace("  保留原始数据", ""))) {}
PacketModel::PacketModel(SessionStore *s, QObject *p) : QAbstractTableModel(p), store_(s) {
    connect(&i18n::language(), &i18n::Language::changed, this, &PacketModel::retranslate);
}
void PacketModel::retranslate() {
    for (auto &row : visible_) {
        row.protocol = i18n::text(QString::fromStdString(row.packet->protocol));
        row.summary =
            i18n::text(QString::fromStdString(row.packet->summary).replace("  保留原始数据", ""));
    }
    emit headerDataChanged(Qt::Horizontal, 0, 7);
    if (!visible_.empty())
        emit dataChanged(index(0, 0), index(rowCount() - 1, 7));
}
int PacketModel::rowCount(const QModelIndex &p) const {
    return p.isValid() ? 0 : static_cast<int>(visible_.size());
}
int PacketModel::columnCount(const QModelIndex &p) const {
    return p.isValid() ? 0 : 8;
}
QVariant PacketModel::data(const QModelIndex &i, int role) const {
    if (!i.isValid() || i.row() < 0 || i.row() >= rowCount())
        return {};
    const auto &row = visible_[i.row()];
    const auto &p = *row.packet;
    if (role == Qt::ToolTipRole) {
        QString result = row.summary;
        if (i.column() == 2)
            result = row.source;
        else if (i.column() == 3)
            result = row.destination;
        if (!p.error.empty())
            result += "\n" + i18n::text(QString::fromStdString(p.error));
        for (const auto &warning : p.warnings)
            result += "\n" + i18n::text(QString::fromStdString(warning));
        return result;
    }
    if (role == Qt::AccessibleTextRole && i.column() == 0)
        return QString::number(p.id) +
               (!p.error.empty() ? ", " + i18n::text("异常")
                                 : (p.warnings.empty() ? QString{} : ", " + i18n::text("提示")));
    if (role == Qt::FontRole && i.column() != 4 && i.column() != 6 && i.column() != 7) {
        static const auto mono = style::dataFont();
        return mono;
    }
    if (role == Qt::DecorationRole && i.column() == 0 &&
        (!p.error.empty() || !p.warnings.empty())) {
        return icons::icon(!p.error.empty() ? icons::Id::Error : icons::Id::Warning, false, 14);
    }
    if (role != Qt::DisplayRole)
        return {};
    switch (i.column()) {
    case 0:
        return QVariant::fromValue<qulonglong>(p.id);
    case 1:
        return row.time;
    case 2:
        return row.source;
    case 3:
        return row.destination;
    case 4:
        return row.protocol;
    case 5:
        return static_cast<qulonglong>(p.raw.bytes.size());
    case 6:
        return !p.error.empty() ? i18n::text("异常")
                                : (p.warnings.empty() ? QString{} : i18n::text("提示"));
    case 7:
        return row.summary;
    }
    return {};
}
QVariant PacketModel::headerData(int n, Qt::Orientation o, int role) const {
    static const QStringList names = {"序号", "时间", "源地址", "目的地址",
                                      "协议", "字节", "状态",   "摘要"};
    return o == Qt::Horizontal && role == Qt::DisplayRole && n >= 0 && n < names.size()
               ? i18n::text(names[n])
               : QVariant{};
}
void PacketModel::rebuild() {
    visible_.clear();
    for (const auto &p : store_->packets())
        if (matches(*p))
            visible_.emplace_back(p);
}
void PacketModel::setStore(SessionStore *store) {
    beginResetModel();
    store_ = store;
    filter_.tcpConversationId.reset();
    rebuild();
    endResetModel();
}
void PacketModel::append(std::vector<Packet> packets) {
    if (packets.empty())
        return;
    const auto previousLast = store_->packets().empty() ? 0 : store_->packets().back()->id;
    for (auto &p : packets)
        store_->append(std::move(p));
    const auto &retained = store_->packets();
    // Only expired rows leave the model. Surviving indexes and selections stay valid.
    const auto first =
        retained.empty() ? visible_.end()
                         : std::lower_bound(visible_.begin(), visible_.end(), retained.front()->id,
                                            [](const auto &row, std::uint64_t id) {
                                                return row.packet->id < id;
                                            });
    const int removed = static_cast<int>(first - visible_.begin());
    if (removed) {
        beginRemoveRows({}, 0, removed - 1);
        for (int i = 0; i < removed; ++i)
            visible_.pop_front();
        endRemoveRows();
    }
    const auto next =
        std::upper_bound(retained.begin(), retained.end(), previousLast,
                         [](std::uint64_t id, const auto &packet) { return id < packet->id; });
    std::vector<std::shared_ptr<const Packet>> added;
    added.reserve(static_cast<std::size_t>(std::distance(next, retained.end())));
    for (auto it = next; it != retained.end(); ++it)
        if (matches(**it))
            added.push_back(*it);
    if (!added.empty()) {
        const int start = rowCount();
        beginInsertRows({}, start, start + static_cast<int>(added.size()) - 1);
        for (auto &packet : added)
            visible_.emplace_back(std::move(packet));
        endInsertRows();
    }
}
void PacketModel::clear() {
    beginResetModel();
    store_->clear();
    filter_.tcpConversationId.reset();
    rebuild();
    endResetModel();
}
void PacketModel::setFilter(FilterSpec f) {
    if (f == filter_)
        return;
    beginResetModel();
    filter_ = std::move(f);
    rebuild();
    endResetModel();
}
std::shared_ptr<const Packet> PacketModel::packetAt(int row) const {
    return row >= 0 && row < rowCount() ? visible_[row].packet : nullptr;
}
int PacketModel::rowForId(std::uint64_t id) const {
    const auto it = std::lower_bound(
        visible_.begin(), visible_.end(), id,
        [](const auto &row, std::uint64_t value) { return row.packet->id < value; });
    return it != visible_.end() && it->packet->id == id ? static_cast<int>(it - visible_.begin())
                                                        : -1;
}
bool PacketModel::matches(const Packet &packet) const {
    ++evaluations_;
    return filter_.matches(packet) &&
           (!expression_ ||
            expression_->evaluate(packet, applications_ ? applications_->facts(packet.id)
                                                        : nullptr) == FilterTruth::True);
}
void PacketModel::setExpression(std::shared_ptr<const DisplayExpression> expression) {
    beginResetModel();
    expression_ = std::move(expression);
    rebuild();
    endResetModel();
}
void PacketModel::setApplicationIndex(const ApplicationIndex *index) {
    applications_ = index;
}
void PacketModel::refreshApplications(const IndexDelta &changes) {
    if (!expression_ || !expression_->requiresApplications())
        return;
    for (const auto id : changes.packets) {
        const auto packet = store_->find(id);
        const auto found = std::lower_bound(
            visible_.begin(), visible_.end(), id,
            [](const auto &row, std::uint64_t value) { return row.packet->id < value; });
        const bool present = found != visible_.end() && found->packet->id == id;
        const bool wanted = packet && matches(*packet);
        const int row = static_cast<int>(found - visible_.begin());
        if (present && !wanted) {
            beginRemoveRows({}, row, row);
            visible_.erase(found);
            endRemoveRows();
        } else if (!present && wanted) {
            beginInsertRows({}, row, row);
            visible_.emplace(found, packet);
            endInsertRows();
        }
    }
}
void PacketModel::refreshApplications() {
    if (!expression_ || !expression_->requiresApplications())
        return;
    std::vector<std::shared_ptr<const Packet>> desired;
    for (const auto &p : store_->packets())
        if (matches(*p))
            desired.push_back(p);
    // Reconcile sorted packet IDs so surviving selection and scrolling stay stable.
    std::size_t row = 0, next = 0;
    while (row < visible_.size() || next < desired.size()) {
        if (row < visible_.size() && next < desired.size() &&
            visible_[row].packet == desired[next]) {
            ++row;
            ++next;
            continue;
        }
        if (row < visible_.size() &&
            (next == desired.size() || visible_[row].packet->id < desired[next]->id)) {
            auto end = row + 1;
            while (end < visible_.size() &&
                   (next == desired.size() || visible_[end].packet->id < desired[next]->id))
                ++end;
            beginRemoveRows({}, static_cast<int>(row), static_cast<int>(end - 1));
            visible_.erase(visible_.begin() + static_cast<std::ptrdiff_t>(row),
                           visible_.begin() + static_cast<std::ptrdiff_t>(end));
            endRemoveRows();
        } else {
            auto end = next + 1;
            while (end < desired.size() &&
                   (row == visible_.size() || desired[end]->id < visible_[row].packet->id))
                ++end;
            beginInsertRows({}, static_cast<int>(row), static_cast<int>(row + end - next - 1));
            for (auto at = next; at < end; ++at)
                visible_.emplace(visible_.begin() + static_cast<std::ptrdiff_t>(row + at - next),
                                 desired[at]);
            endInsertRows();
            row += end - next;
            next = end;
        }
    }
}
} // namespace etherscope
