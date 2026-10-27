#include "ui/tcp_dialog.h"
#include "ui/helpers.h"
#include "ui/style.h"
#include "ui/language.h"
#include "ui/stream_pane.h"
#include "ui/icons.h"
#include "ui/flow_layout.h"
#include <QAbstractTableModel>
#include <QDateTime>
#include <QCloseEvent>
#include <QFontDatabase>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTableView>
#include <QTabWidget>
#include <QTimer>
#include <QShortcut>
#include <QKeyEvent>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <algorithm>

namespace etherscope {
namespace {
QString stateText(TcpState state) {
    switch (state) {
    case TcpState::Midstream:
        return i18n::text("中途捕获");
    case TcpState::Handshake:
        return i18n::text("握手未完整");
    case TcpState::Established:
        return i18n::text("握手完成");
    case TcpState::Closing:
        return i18n::text("FIN 已见");
    case TcpState::Closed:
        return i18n::text("FIN 已确认");
    case TcpState::Reset:
        return i18n::text("RST 已见");
    }
    return "-";
}
QString eventText(TcpEventKind kind) {
    switch (kind) {
    case TcpEventKind::Syn:
        return "SYN";
    case TcpEventKind::SynAck:
        return "SYN ACK";
    case TcpEventKind::Handshake:
        return i18n::text("握手完成");
    case TcpEventKind::Fin:
        return "FIN";
    case TcpEventKind::Reset:
        return "RST";
    case TcpEventKind::FinAcknowledged:
        return i18n::text("FIN 确认");
    }
    return "-";
}
QString milliseconds(std::optional<std::uint64_t> value) {
    return value ? QString::number(double(*value) / 1000000, 'f', 3) : QString("-");
}
struct Row {
    std::uint64_t id{};
    std::array<QVariant, 12> values;
};
} // namespace
class TcpTableModel final : public QAbstractTableModel {
  public:
    explicit TcpTableModel(QObject *parent) : QAbstractTableModel(parent) {
        connect(&i18n::language(), &i18n::Language::changed, this,
                [this] { emit headerDataChanged(Qt::Horizontal, 0, 11); });
    }
    int rowCount(const QModelIndex &parent = {}) const override {
        return parent.isValid() ? 0 : static_cast<int>(rows_.size());
    }
    int columnCount(const QModelIndex &parent = {}) const override {
        return parent.isValid() ? 0 : 12;
    }
    QVariant data(const QModelIndex &index, int role) const override {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() ||
            index.column() < 0 || index.column() >= 12)
            return {};
        const auto &row = rows_[index.row()];
        if (role == Qt::UserRole)
            return QVariant::fromValue<qulonglong>(row.id);
        if (role == Qt::DisplayRole || role == Qt::ToolTipRole)
            return row.values[index.column()];
        if (role == Qt::FontRole && index.column() != 5)
            return style::dataFont();
        return {};
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        static const QStringList titles = {"会话",        "地址 A",      "端口 A",    "地址 B",
                                           "端口 B",      "状态",        "A -> B 包", "B -> A 包",
                                           "A -> B 字节", "B -> A 字节", "握手 ms",   "持续 s"};
        return orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 &&
                       section < titles.size()
                   ? i18n::text(titles[section])
                   : QVariant{};
    }
    void refresh(const TcpConversations &tracker) {
        std::vector<Row> next;
        next.reserve(tracker.items().size());
        for (const auto &c : tracker.items()) {
            const auto duration =
                static_cast<std::uint64_t>(c.lastNs) - static_cast<std::uint64_t>(c.firstNs);
            Row row;
            row.id = c.id;
            row.values = {
                QVariant::fromValue<qulonglong>(c.id),
                q(formatEndpointAddress(c.key.a)),
                c.key.a.port,
                q(formatEndpointAddress(c.key.b)),
                c.key.b.port,
                stateText(c.state),
                QVariant::fromValue<qulonglong>(c.packets[0]),
                QVariant::fromValue<qulonglong>(c.packets[1]),
                QVariant::fromValue<qulonglong>(c.wireBytes[0]),
                QVariant::fromValue<qulonglong>(c.wireBytes[1]),
                c.handshakeNs ? QVariant(double(*c.handshakeNs) / 1000000) : QVariant("-"),
                c.hasTimestamps ? QVariant(double(duration) / 1000000000) : QVariant("-")};
            next.push_back(std::move(row));
        }
        std::sort(next.begin(), next.end(),
                  [](const auto &a, const auto &b) { return a.id < b.id; });
        const bool same = rows_.size() == next.size() &&
                          std::equal(rows_.begin(), rows_.end(), next.begin(),
                                     [](const auto &a, const auto &b) { return a.id == b.id; });
        if (!same)
            beginResetModel();
        rows_ = std::move(next);
        if (!same)
            endResetModel();
        else if (!rows_.empty())
            emit dataChanged(index(0, 0), index(rowCount() - 1, 11));
    }

  private:
    std::vector<Row> rows_;
};
TcpPanel::TcpPanel(QWidget *parent, StreamDecoder decoder) : QWidget(parent) {
    setObjectName("tcpDialog");
    setWindowTitle("TCP 会话");
    resize(1200, 640);
    setMinimumSize(460, 260);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(style::margin, style::margin, style::margin, style::margin);
    layout->setSpacing(style::gap);
    auto *summary = new FlowLayout;
    summary->setSpacing(12);
    mode_ = new QLabel(this);
    mode_->setObjectName("tcpMode");
    summary->addWidget(mode_);
    auto cell = [&](const QString &name, const QString &objectName) {
        summary->addWidget(new QLabel(name, this));
        auto *label = new QLabel(this);
        label->setObjectName(objectName);
        summary->addWidget(label);
        return label;
    };
    count_ = cell("会话", "tcpCount");
    overwritten_ = cell("覆盖", "tcpOverwritten");
    skipped_ = cell("跳过", "tcpSkipped");
    memory_ = cell("占用", "tcpMemory");
    layout->addLayout(summary);
    auto *splitter = new QSplitter(Qt::Vertical, this);
    splitter->setChildrenCollapsible(false);
    layout->addWidget(splitter, 1);
    table_ = new QTableView(splitter);
    table_->setObjectName("tcpTable");
    model_ = new TcpTableModel(this);
    auto *proxy = new QSortFilterProxyModel(this);
    proxy->setSourceModel(model_);
    proxy->setDynamicSortFilter(true);
    table_->setModel(proxy);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setShowGrid(false);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(style::rowHeight);
    table_->setSortingEnabled(true);
    table_->sortByColumn(0, Qt::AscendingOrder);
    const int widths[] = {56, 174, 64, 174, 64, 100, 76, 76, 94, 94, 86, 82};
    for (int i = 0; i < 12; ++i)
        table_->setColumnWidth(i, widths[i]);
    auto *lower = new QWidget(splitter);
    auto *details = new QVBoxLayout(lower);
    details->setContentsMargins(0, 0, 0, 0);
    details->setSpacing(style::gap);
    auto *metrics = new FlowLayout;
    const QStringList titles = {"SYN 应答 ms", "握手 ms",    "SYN 重复",   "RST",
                                "VLAN",        "A 载荷字节", "B 载荷字节", "事件覆盖"};
    for (int i = 0; i < 8; ++i) {
        auto *pair = new QWidget(lower);
        auto *pairLayout = new QHBoxLayout(pair);
        pairLayout->setContentsMargins(0, 0, 0, 0);
        pairLayout->addWidget(new QLabel(titles[i], pair));
        metrics_[i] = new QLabel("-", lower);
        metrics_[i]->setObjectName("tcpMetric" + QString::number(i));
        pairLayout->addWidget(metrics_[i]);
        metrics->addWidget(pair);
    }
    details->addLayout(metrics);
    tabs_ = new QTabWidget(lower);
    tabs_->setObjectName("tcpAnalysisTabs");
    details->addWidget(tabs_, 1);
    events_ = new QTreeWidget(tabs_);
    events_->setObjectName("tcpEvents");
    events_->setHeaderLabels({"包号", "时间", "方向", "事件", "SEQ", "ACK"});
    events_->setRootIsDecorated(false);
    events_->setAlternatingRowColors(true);
    events_->setSelectionMode(QAbstractItemView::SingleSelection);
    events_->setFont(style::dataFont());
    events_->setColumnWidth(0, 70);
    events_->setColumnWidth(1, 130);
    events_->setColumnWidth(2, 88);
    events_->setColumnWidth(3, 120);
    tabs_->addTab(events_, "事件");
    stream_ = new StreamPane(tabs_, std::move(decoder));
    tabs_->addTab(stream_, "流数据");
    splitter->setSizes({300, 260});
    auto *actions = new FlowLayout;
    filter_ = new QPushButton("查看报文", this);
    filter_->setObjectName("tcpFilterButton");
    locate_ = new QPushButton("定位", this);
    locate_->setObjectName("tcpLocateButton");
    auto *close = new QPushButton("关闭", this);
    icons::bind(filter_, icons::Id::Filter);
    icons::bind(locate_, icons::Id::Locate);
    icons::bind(close, icons::Id::Close);
    error_ = new QLabel(this);
    error_->setObjectName("tcpError");
    error_->setProperty("error", true);
    error_->setWordWrap(true);
    error_->setMaximumWidth(420);
    streamButton_ = new QPushButton("流数据", this);
    icons::bind(streamButton_, icons::Id::Tcp);
    streamButton_->setObjectName("tcpStreamButton");
    streamButton_->setEnabled(false);
    actions->addWidget(filter_);
    actions->addWidget(locate_);
    actions->addWidget(streamButton_);
    actions->addWidget(error_);
    actions->addWidget(close);
    layout->addLayout(actions);
    connect(table_->selectionModel(), &QItemSelectionModel::currentRowChanged, this, [this] {
        if (!refreshing_)
            renderSelection();
    });
    connect(filter_, &QPushButton::clicked, this, [this] {
        if (store_ && selectedId())
            emit filterRequested(selectedId(), generation_, store_);
    });
    connect(locate_, &QPushButton::clicked, this, &TcpPanel::locate);
    connect(events_, &QTreeWidget::itemDoubleClicked, this, [this] { locate(); });
    connect(events_, &QTreeWidget::currentItemChanged, this, [this] {
        locate_->setEnabled(navigationEnabled_ && tabs_->currentIndex() == 0 && events_->currentItem() != nullptr);
    });
    connect(tabs_, &QTabWidget::currentChanged, this, [this](int index) {
        locate_->setVisible(index == 0);
        locate_->setEnabled(navigationEnabled_ && index == 0 && events_->currentItem() != nullptr);
    });
    connect(close, &QPushButton::clicked, this, &QWidget::close);
    filter_->setEnabled(false);
    locate_->setEnabled(false);
    connect(streamButton_, &QPushButton::clicked, this, [this, splitter] {
        if (!streamExpanded_) {
            splitter->setSizes({180, 380});
            streamExpanded_ = true;
        }
        tabs_->setCurrentIndex(1);
        stream_->start();
    });
    connect(stream_, &StreamPane::locateRequested, this, [this](quint64 id) {
        if (store_ && !closing_)
            emit locateRequested(id, generation_, store_);
    });
    connect(stream_, &StreamPane::workChanged, this, [this] {
        emit workChanged();
        if (closing_ && !stream_->busy())
            QTimer::singleShot(0, this, &QWidget::close);
    });
    connect(stream_, &StreamPane::filterRequested, this, &TcpPanel::expressionRequested);
    connect(stream_, &StreamPane::analysisHelpRequested, this, &TcpPanel::analysisHelpRequested);
    auto *escape = new QShortcut(QKeySequence(Qt::Key_Escape), this);
    escape->setContext(Qt::WidgetWithChildrenShortcut);
    connect(escape, &QShortcut::activated, this, &QWidget::close);
    i18n::bind(this);
    connect(&i18n::language(), &i18n::Language::changed, this, [this] {
        if (store_) {
            revision_ = 0;
            refresh(*store_, mode_->property("_languageSource").toString());
        }
    });
}
std::uint64_t TcpPanel::selectedId() const {
    return table_->currentIndex().data(Qt::UserRole).toULongLong();
}
void TcpPanel::setApplicationIndex(const ApplicationIndex *index) {
    stream_->setApplicationIndex(index);
}
void TcpPanel::refresh(const SessionStore &store, const QString &mode) {
    if (store_ == &store && generation_ == store.tcp().generation() &&
        revision_ == store.tcp().revision())
        return;
    const bool same = store_ == &store && generation_ == store.tcp().generation();
    const auto selected = same ? selectedId() : 0;
    if (!same) {
        selectFirst_ = true;
        stream_->setSelection(nullptr, 0);
    }
    store_ = &store;
    generation_ = store.tcp().generation();
    revision_ = store.tcp().revision();
    i18n::setLabel(mode_, mode);
    refreshing_ = true;
    model_->refresh(store.tcp());
    table_->clearSelection();
    table_->setCurrentIndex({});
    selectConversation(selected);
    refreshing_ = false;
    if (!selected && selectFirst_ && table_->model()->rowCount())
        table_->setCurrentIndex(table_->model()->index(0, 0));
    count_->setText(QString::number(store.tcp().items().size()));
    overwritten_->setText(QString::number(store.tcp().overwritten()));
    skipped_->setText(QString::number(store.tcp().skipped()));
    memory_->setText(QString::number(double(store.tcp().estimatedBytes()) / 1024, 'f', 1) + " KiB");
    renderSelection();
}
void TcpPanel::selectConversation(std::uint64_t id) {
    if (!id)
        return;
    for (int row = 0; row < table_->model()->rowCount(); ++row)
        if (table_->model()->index(row, 0).data(Qt::UserRole).toULongLong() == id) {
            table_->setCurrentIndex(table_->model()->index(row, 0));
            return;
        }
}
void TcpPanel::renderSelection() {
    i18n::setLabel(error_, {});
    const auto *item = store_ ? store_->tcp().find(selectedId()) : nullptr;
    const auto selectedEvent =
        events_->currentItem() ? events_->currentItem()->data(0, Qt::UserRole).toULongLong() : 0;
    if (item)
        selectFirst_ = false;
    stream_->setSelection(store_, item ? item->id : 0);
    streamButton_->setEnabled(item != nullptr);
    events_->clear();
    filter_->setEnabled(navigationEnabled_ && item != nullptr);
    locate_->setEnabled(false);
    for (auto *metric : metrics_)
        metric->setText("-");
    if (!item)
        return;
    const std::array<QString, 8> values = {milliseconds(item->synAckNs),
                                           milliseconds(item->handshakeNs),
                                           QString::number(item->synRepeats),
                                           QString::number(item->resets),
                                           item->key.vlan ? QString::number(*item->key.vlan)
                                                          : QString("-"),
                                           QString::number(item->payloadBytes[0]),
                                           QString::number(item->payloadBytes[1]),
                                           QString::number(item->eventsOverwritten)};
    for (std::size_t i = 0; i < values.size(); ++i)
        metrics_[i]->setText(values[i]);
    for (std::size_t i = 0; i < item->eventCount; ++i) {
        const auto &event = item->events[(item->eventStart + i) % item->eventLimit];
        auto *row = new QTreeWidgetItem(
            events_,
            {QString::number(event.packetId),
             event.timestampValid ? QDateTime::fromMSecsSinceEpoch(event.timestampNs / 1000000)
                                        .toString("HH:mm:ss.zzz")
                                  : QString("-"),
             event.direction == 0 ? "A -> B" : "B -> A", eventText(event.kind),
             QString::number(event.sequence), QString::number(event.acknowledgment)});
        row->setData(0, Qt::UserRole, QVariant::fromValue<qulonglong>(event.packetId));
        if (event.packetId == selectedEvent)
            events_->setCurrentItem(row);
    }
    if (!events_->currentItem() && events_->topLevelItemCount())
        events_->setCurrentItem(events_->topLevelItem(0));
}
void TcpPanel::locate() {
    if (navigationEnabled_ && store_ && events_->currentItem())
        emit locateRequested(events_->currentItem()->data(0, Qt::UserRole).toULongLong(),
                             generation_, store_);
}
void TcpPanel::showError(const QString &error) {
    i18n::setLabel(error_, error);
}
bool TcpPanel::streamBusy() const {
    return stream_->busy();
}
void TcpPanel::setSourceContext(SourceContext context) { stream_->setSourceContext(context); }
void TcpPanel::updateAnalysisContext(SourceContext context) { stream_->setSourceContext(context, false); }
void TcpPanel::invalidate() {
    stream_->setSelection(nullptr, 0);
    store_ = nullptr;
    TcpConversations empty;
    model_->refresh(empty);
    renderSelection();
    count_->setText("0");
}
void TcpPanel::setNavigationEnabled(bool enabled) {
    navigationEnabled_ = enabled;
    filter_->setEnabled(enabled && selectedId());
    locate_->setEnabled(enabled && tabs_->currentIndex() == 0 && events_->currentItem());
    stream_->setNavigationEnabled(enabled);
}
void TcpPanel::keyPressEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_Escape) {
        close();
        event->accept();
    } else QWidget::keyPressEvent(event);
}
void TcpPanel::closeEvent(QCloseEvent *event) {
    if (stream_->busy()) {
        event->ignore();
        closing_ = true;
        setEnabled(false);
        stream_->cancel();
        return;
    }
    closing_ = false;
    setEnabled(true);
    event->accept();
    emit closed();
}
} // namespace etherscope
