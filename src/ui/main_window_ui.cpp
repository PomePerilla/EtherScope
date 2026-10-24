#include "ui/main_window.h"
#include "ui/filter_chip.h"
#include "ui/style.h"
#include "ui/language.h"
#include "ui/helpers.h"
#include "ui/icons.h"
#include "ui/flow_layout.h"
#include "ui/window_title_bar.h"
#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFontDatabase>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QResizeEvent>
#include <QShortcut>
#include <QSplitter>
#include <QStatusBar>
#include <QTabBar>
#include <QTableView>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QStandardItemModel>
#include <QTreeView>
#include <QToolButton>

namespace etherscope {
namespace {
QWidget *panel(const QString &name, QWidget *content, QWidget *parent) {
    auto *frame = new QWidget(parent);
    auto *layout = new QVBoxLayout(frame);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    auto *label = new QLabel(name, frame);
    label->setObjectName("panelTitle");
    label->setFixedHeight(style::titleHeight);
    layout->addWidget(label);
    layout->addWidget(content, 1);
    return frame;
}
void addDirections(QComboBox *box) {
    box->addItems({"任一方向", "源地址", "目的地址"});
    box->setMinimumWidth(88);
}
} // namespace
void MainWindow::buildUi() {
    setObjectName("mainWindow");
    setWindowFlags(windowFlags() | Qt::FramelessWindowHint);
    setWindowTitle("EtherScope");
    QIcon applicationIcon;
    for (int size : {16, 20, 24, 32, 48, 64, 128, 256})
        applicationIcon.addFile(QString(":/icons/app-%1.png").arg(size), QSize(size, size));
    setWindowIcon(applicationIcon);
    qApp->setWindowIcon(windowIcon());
    setMinimumSize(900, 580);
    resize(1360, 860);
    auto *root = new QWidget(this);
    root->setObjectName("workspace");
    auto *layout = new QVBoxLayout(root);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    titleBar_ = new WindowTitleBar(this, root);
    layout->addWidget(titleBar_);
    auto *toolbarBar = new QWidget(root);
    toolbarBar->setObjectName("toolbarBar");
    auto *toolbar = new QHBoxLayout(toolbarBar);
    toolbar->setContentsMargins(style::margin, 6, style::margin, 6);
    toolbar->setSpacing(style::gap);
    toolbar->addWidget(new QLabel("网卡", toolbarBar));
    devices_ = new QComboBox(toolbarBar);
    devices_->setObjectName("deviceSelector");
    devices_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    devices_->setMinimumContentsLength(12);
    devices_->setMinimumWidth(150);
    devices_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    auto *deviceModel = new QStandardItemModel(0, 2, devices_);
    deviceModel->setHorizontalHeaderLabels({"名称", "地址"});
    devices_->setModel(deviceModel);
    devices_->setModelColumn(0);
    auto *deviceView = new QTreeView(devices_);
    deviceView->setRootIsDecorated(false);
    deviceView->setItemsExpandable(false);
    deviceView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    deviceView->setSelectionBehavior(QAbstractItemView::SelectRows);
    deviceView->setMinimumWidth(640);
    devices_->setView(deviceView);
    start_ = new QPushButton("开始", toolbarBar);
    start_->setObjectName("startButton");
    start_->setProperty("accent", true);
    stop_ = new QPushButton("停止", toolbarBar);
    stop_->setObjectName("stopButton");
    open_ = new QPushButton("打开", toolbarBar);
    open_->setObjectName("openButton");
    save_ = new QPushButton("保存", toolbarBar);
    save_->setObjectName("saveButton");
    auto *more = new QPushButton("更多", toolbarBar);
    more->setObjectName("moreButton");
    auto *menu = new QMenu(more);
    auto *captureMenu = menu->addMenu("捕获设置");
    captureMenu->setObjectName("captureSettingsMenu");
    refresh_ = captureMenu->addAction("刷新接口");
    refresh_->setObjectName("refreshAction");
    refresh_->setShortcut(QKeySequence(Qt::Key_F5));
    addAction(refresh_);
    captureFilterAction_ = captureMenu->addAction("捕获过滤");
    captureFilterAction_->setObjectName("captureFilterAction");
    connect(captureFilterAction_, &QAction::triggered, this, &MainWindow::configureCaptureFilter);
    auto *analysis = new QPushButton("分析", toolbarBar);
    analysis->setObjectName("analysisButton");
    auto *analysisMenu = new QMenu(analysis);
    analysisMenu->setObjectName("analysisMenu");
    analysis->setMenu(analysisMenu);
    auto *tcpAction = analysisMenu->addAction("TCP 会话");
    tcpAction->setObjectName("tcpConversationsAction");
    connect(tcpAction, &QAction::triggered, this, &MainWindow::showTcpConversations);
    auto *appAction = analysisMenu->addAction("Application analysis");
    applicationAction_ = appAction;
    appAction->setObjectName("applicationAnalysisAction");
    connect(appAction, &QAction::triggered, this, &MainWindow::showApplicationAnalysis);
    expressionAction_ = new QAction("Display expression", this);
    expressionAction_->setObjectName("expressionAction");
    expressionAction_->setCheckable(true);
    auto *keysMenu = menu->addMenu("TLS key log");
    auto *loadKey = keysMenu->addAction("打开");
    loadKey->setObjectName("tlsKeyLogOpen");
    connect(loadKey, &QAction::triggered, this, [this] {
        const auto path = QFileDialog::getOpenFileName(
            this, i18n::text("TLS key log"), usableDirectory(keyDirectory_),
            "Key log (*.log *.txt);;All files (*)", nullptr, QFileDialog::DontUseNativeDialog);
        if (!path.isEmpty())
            setTlsKeyLog(path);
    });
    connect(keysMenu->addAction("Reload"), &QAction::triggered, this, [this] {
        for (auto &service : applications_)
            service->reloadKeyLog();
    });
    connect(keysMenu->addAction("移除"), &QAction::triggered, this, [this] { setTlsKeyLog({}); });
    recordingAction_ = captureMenu->addAction("Record to disk");
    recordingAction_->setObjectName("recordingAction");
    recordingAction_->setCheckable(true);
    connect(recordingAction_, &QAction::toggled, this,
            [this](bool checked) { recordingOptions_.enabled = checked; });
    recordingSettingsAction_ = captureMenu->addAction("Recording settings");
    recordingSettingsAction_->setObjectName("recordingSettingsAction");
    connect(recordingSettingsAction_, &QAction::triggered, this, &MainWindow::configureRecording);
    bpfMarker_ = new QLabel("BPF", toolbarBar);
    bpfMarker_->setObjectName("bpfMarker");
    bpfMarker_->hide();
    auto *appearance = menu->addMenu("外观与语言");
    appearance->setObjectName("appearanceMenu");
    theme_ = appearance->addAction("深色主题");
    theme_->setObjectName("darkThemeAction");
    theme_->setCheckable(true);
    auto *languages = appearance->addMenu("语言");
    languages->setObjectName("languageMenu");
    auto *languageGroup = new QActionGroup(languages);
    for (const auto &entry : std::array<std::pair<const char *, const char *>, 3>{
             {{"en", "English"}, {"zh_CN", "简体中文"}, {"zh_TW", "繁體中文"}}}) {
        auto *action = languages->addAction(QString::fromUtf8(entry.second));
        action->setObjectName("language_" + QString(entry.first));
        action->setData(entry.first);
        action->setCheckable(true);
        languageGroup->addAction(action);
        action->setProperty("_languageBound", true);
        connect(action, &QAction::triggered, this,
                [code = QString(entry.first)] { i18n::language().set(code); });
    }
    menu->addSeparator();
    menu->addAction("EtherScope " + QCoreApplication::applicationVersion())->setEnabled(false);
    more->setMenu(menu);
    toolbar->addWidget(devices_, 1);
    auto *refreshButton = new QToolButton(toolbarBar);
    refreshButton->setObjectName("refreshButton");
    refreshButton->setDefaultAction(refresh_);
    refreshButton->setToolButtonStyle(Qt::ToolButtonIconOnly);
    refreshButton->setAccessibleName("刷新接口");
    toolbar->addWidget(refreshButton);
    auto *toolbarActions = new QWidget(toolbarBar);
    toolbarActions->setObjectName("toolbarActions");
    auto *actionFlow = new FlowLayout(toolbarActions, 4);
    for (auto *b : {start_, stop_, open_, save_, analysis, more})
        actionFlow->addWidget(b);
    toolbar->addWidget(toolbarActions);
    icons::bind(start_, icons::Id::Start, true);
    icons::bind(stop_, icons::Id::Stop);
    icons::bind(open_, icons::Id::Open);
    icons::bind(save_, icons::Id::Save);
    icons::bind(analysis, icons::Id::Application);
    icons::bind(more, icons::Id::More);
    icons::bind(refresh_, icons::Id::Refresh);
    icons::bind(captureFilterAction_, icons::Id::Filter);
    icons::bind(tcpAction, icons::Id::Tcp);
    icons::bind(appAction, icons::Id::Application);
    icons::bind(expressionAction_, icons::Id::Expression);
    icons::bind(loadKey, icons::Id::Open);
    icons::bind(keysMenu->menuAction(), icons::Id::Key);
    icons::bind(recordingAction_, icons::Id::Record);
    icons::bind(recordingSettingsAction_, icons::Id::Record);
    icons::bind(captureMenu->menuAction(), icons::Id::Filter);
    icons::bind(appearance->menuAction(), icons::Id::Theme);
    icons::bind(theme_, icons::Id::Theme);
    icons::bind(languages->menuAction(), icons::Id::Language);
    layout->addWidget(toolbarBar);

    auto *sessionStrip = new QWidget(root);
    sessionStrip->setObjectName("sessionStrip");
    auto *sessionLayout = new QVBoxLayout(sessionStrip);
    sessionLayout->setContentsMargins(style::margin, 4, style::margin, 4);
    sessionLayout->setSpacing(4);
    auto *sessionBar = new FlowLayout;
    sessionLayout->addLayout(sessionBar);
    sessionBar->setSpacing(style::gap);
    modes_ = new QTabBar(sessionStrip);
    modes_->setObjectName("sessionTabs");
    modes_->addTab("实时");
    modes_->addTab("文件");
    sessionBar->addWidget(modes_);
    protocol_ = new QComboBox(sessionStrip);
    protocol_->setObjectName("protocolFilter");
    protocol_->addItems(
        {"全部协议", "ICMP", "ARP", "TCP", "UDP", "IPv4", "Ethernet", "IPv6", "ICMPv6"});
    sessionBar->addWidget(protocol_);
    icmpTypeGroup_ = new QWidget(sessionStrip);
    icmpTypeGroup_->setObjectName("icmpTypeGroup");
    auto *typeBar = new QHBoxLayout(icmpTypeGroup_);
    typeBar->setContentsMargins(0, 0, 0, 0);
    typeBar->setSpacing(style::gap);
    typeBar->addWidget(new QLabel("类型", icmpTypeGroup_));
    icmpType_ = new QComboBox(icmpTypeGroup_);
    icmpType_->setObjectName("icmpTypeFilter");
    icmpType_->addItem("全部", -1);
    icmpType_->addItem("回显请求", 8);
    icmpType_->addItem("回显应答", 0);
    icmpType_->addItem("时间超过", 11);
    icmpType_->addItem("目的不可达", 3);
    typeBar->addWidget(icmpType_);
    sessionBar->addWidget(icmpTypeGroup_);
    icmpTypeGroup_->hide();
    addressToggle_ = new QPushButton("地址筛选", sessionStrip);
    addressToggle_->setObjectName("addressFilterToggle");
    addressToggle_->setCheckable(true);
    sessionBar->addWidget(addressToggle_);
    icons::bind(addressToggle_, icons::Id::Filter);
    expressionToggle_ = new QToolButton(sessionStrip);
    expressionToggle_->setObjectName("expressionToggle");
    expressionToggle_->setDefaultAction(expressionAction_);
    expressionToggle_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    sessionBar->addWidget(expressionToggle_);
    sessionBar->addWidget(bpfMarker_);
    conditionStrip_ = new QWidget(sessionStrip);
    conditionStrip_->setObjectName("conditionStrip");
    auto *conditionFlow = new FlowLayout(conditionStrip_);
    sessionLayout->addWidget(conditionStrip_);
    protocolChip_ = new FilterChip(sessionStrip);
    protocolChip_->setObjectName("protocolCondition");
    icmpChip_ = new FilterChip(sessionStrip);
    icmpChip_->setObjectName("icmpCondition");
    macChip_ = new FilterChip(sessionStrip);
    macChip_->setObjectName("macCondition");
    ipChip_ = new FilterChip(sessionStrip);
    ipChip_->setObjectName("ipCondition");
    conversationChip_ = new FilterChip(sessionStrip);
    conversationChip_->setObjectName("tcpConversationCondition");
    expressionChip_ = new FilterChip(sessionStrip);
    expressionChip_->setObjectName("expressionCondition");
    expressionChip_->setMaximumWidth(180);
    for (auto *chip :
         {protocolChip_, icmpChip_, macChip_, ipChip_, conversationChip_, expressionChip_}) {
        conditionFlow->addWidget(chip);
        chip->hide();
    }
    conditionStrip_->hide();
    follow_ = new QCheckBox("跟随", sessionStrip);
    follow_->setObjectName("followLatest");
    follow_->setChecked(true);
    follow_->setToolTip("滚动或选择历史数据包会暂停跟随，勾选后恢复");
    sessionBar->addWidget(follow_);
    statistics_ = new QCheckBox("统计", sessionStrip);
    statistics_->setObjectName("statisticsToggle");
    sessionBar->addWidget(statistics_);
    layout->addWidget(sessionStrip);
    expressionPanel_ = new QWidget(root);
    expressionPanel_->setObjectName("expressionPanel");
    auto *expressionLayout = new QVBoxLayout(expressionPanel_);
    expressionLayout->setContentsMargins(style::margin, 4, style::margin, 4);
    expressionInput_ = new QLineEdit(expressionPanel_);
    expressionInput_->setObjectName("expressionInput");
    expressionInput_->setPlaceholderText("tcp.port == 443 and tls.sni contains \"example\"");
    expressionLayout->addWidget(expressionInput_);
    expressionError_ = new QLabel(expressionPanel_);
    expressionError_->setObjectName("expressionError");
    expressionError_->setProperty("error", true);
    expressionLayout->addWidget(expressionError_);
    expressionError_->hide();
    layout->addWidget(expressionPanel_);
    expressionPanel_->hide();
    connect(expressionAction_, &QAction::toggled, expressionPanel_, &QWidget::setVisible);
    expressionInput_->installEventFilter(this);

    addressPanel_ = new QWidget(root);
    addressPanel_->setObjectName("addressFilterPanel");
    filterLayout_ = new QGridLayout(addressPanel_);
    filterLayout_->setContentsMargins(style::margin, 6, style::margin, 6);
    filterLayout_->setSpacing(style::gap);
    auto addressGroup = [&](const QString &name, const QString &key, QComboBox *&direction,
                            QLineEdit *&input, QLabel *&error) {
        auto *group = new QWidget(addressPanel_);
        auto *column = new QVBoxLayout(group);
        column->setContentsMargins(0, 0, 0, 0);
        column->setSpacing(3);
        auto *row = new QHBoxLayout;
        row->setSpacing(style::gap);
        row->addWidget(new QLabel(name, group));
        direction = new QComboBox(group);
        direction->setObjectName(key + "Direction");
        addDirections(direction);
        row->addWidget(direction);
        input = new QLineEdit(group);
        input->setObjectName(key + "Input");
        input->setClearButtonEnabled(true);
        input->setMinimumWidth(key == "ip" ? 200 : 130);
        row->addWidget(input, 1);
        column->addLayout(row);
        error = new QLabel(group);
        error->setObjectName(key + "Error");
        error->setProperty("error", true);
        error->hide();
        column->addWidget(error);
        return group;
    };
    macGroup_ = addressGroup("MAC", "mac", macDirection_, mac_, macError_);
    ipGroup_ = addressGroup("IP", "ip", ipDirection_, ip_, ipError_);
    ip_->setPlaceholderText("IPv4 / IPv6");
    filterActions_ = new QWidget(addressPanel_);
    auto *actions = new QHBoxLayout(filterActions_);
    actions->setContentsMargins(0, 0, 0, 0);
    actions->setSpacing(style::gap);
    apply_ = new QPushButton("应用", filterActions_);
    apply_->setObjectName("applyFilterButton");
    actions->addWidget(apply_);
    clear_ = new QPushButton("清除", filterActions_);
    clear_->setObjectName("clearFilterButton");
    actions->addWidget(clear_);
    arrangeFilters();
    layout->addWidget(addressPanel_);
    addressPanel_->hide();
    connect(addressToggle_, &QPushButton::toggled, addressPanel_, &QWidget::setVisible);
    connect(addressToggle_, &QPushButton::clicked, this, [this](bool checked) {
        if (checked)
            ip_->setFocus();
    });
    for (auto *child : addressPanel_->findChildren<QWidget *>())
        child->installEventFilter(this);

    auto *vertical = new QSplitter(Qt::Vertical, root);
    vertical->setObjectName("packetDetailSplitter");
    vertical->setChildrenCollapsible(false);
    table_ = new QTableView(vertical);
    table_->setObjectName("packetTable");
    model_ = new PacketModel(&live_, this);
    table_->setModel(model_);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setShowGrid(false);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(style::rowHeight);
    table_->horizontalHeader()->setMinimumSectionSize(44);
    table_->horizontalHeader()->setFixedHeight(28);
    const int widths[] = {64, 106, 190, 190, 74, 60, 52, 240};
    for (int i = 0; i < 8; ++i)
        table_->setColumnWidth(i, widths[i]);
    table_->setColumnHidden(6, true);
    emptyState_ = new QWidget(table_->viewport());
    emptyState_->setObjectName("packetEmptyState");
    auto *emptyLayout = new QVBoxLayout(emptyState_);
    emptyLayout->setContentsMargins(16, 12, 16, 12);
    emptyLayout->setSpacing(8);
    emptyLayout->addStretch();
    emptyTitle_ = new QLabel(emptyState_);
    emptyTitle_->setObjectName("emptyTitle");
    emptyTitle_->setAlignment(Qt::AlignCenter);
    emptyHint_ = new QLabel(emptyState_);
    emptyHint_->setObjectName("emptyHint");
    emptyHint_->setWordWrap(true);
    emptyHint_->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(emptyTitle_);
    emptyLayout->addWidget(emptyHint_);
    auto *emptyActions = new QHBoxLayout;
    emptyActions->addStretch();
    emptyStart_ = new QPushButton("开始", emptyState_);
    emptyOpen_ = new QPushButton("打开", emptyState_);
    emptyRefresh_ = new QPushButton("刷新接口", emptyState_);
    emptyAdjust_ = new QPushButton("调整筛选", emptyState_);
    emptyStart_->setObjectName("emptyStart");
    emptyOpen_->setObjectName("emptyOpen");
    emptyRefresh_->setObjectName("emptyRefresh");
    emptyAdjust_->setObjectName("emptyAdjust");
    for (auto *button : {emptyStart_, emptyOpen_, emptyRefresh_, emptyAdjust_})
        emptyActions->addWidget(button);
    emptyActions->addStretch();
    emptyLayout->addLayout(emptyActions);
    emptyLayout->addStretch();
    icons::bind(emptyStart_, icons::Id::Start);
    icons::bind(emptyOpen_, icons::Id::Open);
    icons::bind(emptyRefresh_, icons::Id::Refresh);
    icons::bind(emptyAdjust_, icons::Id::Filter);
    connect(emptyStart_, &QPushButton::clicked, start_, &QPushButton::click);
    connect(emptyOpen_, &QPushButton::clicked, open_, &QPushButton::click);
    connect(emptyRefresh_, &QPushButton::clicked, refresh_, &QAction::trigger);
    connect(emptyAdjust_, &QPushButton::clicked, this, [this] {
        addressToggle_->setChecked(true);
        expressionAction_->setChecked(bool(model_->expression()));
        if (model_->expression())
            expressionInput_->setFocus();
        else
            ip_->setFocus();
    });
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(table_->horizontalHeader(), &QHeaderView::customContextMenuRequested, this,
            [this](QPoint position) {
                QMenu columns(table_);
                for (int column = 0; column < model_->columnCount(); ++column) {
                    auto *action = columns.addAction(
                        model_->headerData(column, Qt::Horizontal, Qt::DisplayRole).toString());
                    action->setCheckable(true);
                    action->setChecked(!table_->isColumnHidden(column));
                    if (column == 0)
                        action->setEnabled(false);
                    connect(action, &QAction::toggled, this, [this, column](bool visible) {
                        table_->setColumnHidden(column, !visible);
                    });
                }
                columns.exec(table_->horizontalHeader()->mapToGlobal(position));
            });
    auto *lower = new QWidget(vertical);
    auto *lowerLayout = new QVBoxLayout(lower);
    lowerLayout->setContentsMargins(0, 0, 0, 0);
    lowerLayout->setSpacing(0);
    auto *detailHeader = new QWidget(lower);
    detailHeader->setObjectName("detailHeader");
    auto *headerRow = new QHBoxLayout(detailHeader);
    headerRow->setContentsMargins(style::margin, 0, style::margin, 0);
    headerRow->setSpacing(14);
    detailHeader->setFixedHeight(style::titleHeight);
    detailId_ = new QLabel(detailHeader);
    detailId_->setObjectName("detailPacketId");
    headerRow->addWidget(detailId_);
    detailProtocol_ = new QLabel(detailHeader);
    detailProtocol_->setObjectName("detailProtocol");
    headerRow->addWidget(detailProtocol_);
    headerRow->addWidget(new QLabel("捕获", detailHeader));
    detailCaptured_ = new QLabel(detailHeader);
    detailCaptured_->setObjectName("detailCaptured");
    headerRow->addWidget(detailCaptured_);
    headerRow->addWidget(new QLabel("原始", detailHeader));
    detailOriginal_ = new QLabel(detailHeader);
    detailOriginal_->setObjectName("detailOriginal");
    headerRow->addWidget(detailOriginal_);
    detailIssues_ = new QLabel(detailHeader);
    detailIssues_->setObjectName("detailIssues");
    detailIssues_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    headerRow->addWidget(detailIssues_, 1);
    lowerLayout->addWidget(detailHeader);
    auto *detailSplit = new QSplitter(Qt::Horizontal, lower);
    detailSplit->setObjectName("fieldHexSplitter");
    detailSplit->setChildrenCollapsible(false);
    fields_ = new QTreeWidget;
    fields_->setObjectName("fieldTree");
    fields_->setHeaderLabels({"字段", "值"});
    fields_->setColumnWidth(0, 190);
    fields_->setAlternatingRowColors(true);
    fields_->setUniformRowHeights(true);
    fieldEmpty_ = new QLabel("选择数据包以查看字段和字节", fields_->viewport());
    fieldEmpty_->setObjectName("fieldEmptyState");
    fieldEmpty_->setAlignment(Qt::AlignCenter);
    fieldEmpty_->setWordWrap(true);
    fieldEmpty_->setAttribute(Qt::WA_TransparentForMouseEvents);
    fields_->viewport()->installEventFilter(this);
    fields_->header()->setFixedHeight(26);
    panel("字段", fields_, detailSplit);
    auto *bytePanel = new QWidget;
    auto *byteLayout = new QVBoxLayout(bytePanel);
    byteLayout->setContentsMargins(0, 0, 0, 0);
    byteLayout->setSpacing(0);
    hex_ = new QPlainTextEdit(bytePanel);
    hex_->setObjectName("hexView");
    hex_->setReadOnly(true);
    hex_->setLineWrapMode(QPlainTextEdit::NoWrap);
    byteLayout->addWidget(hex_);
    hexPager_ = new QWidget(bytePanel);
    auto *pagerLayout = new QHBoxLayout(hexPager_);
    pagerLayout->setContentsMargins(0, 0, 0, 0);
    previousBytes_ = new QPushButton("上一页", hexPager_);
    previousBytes_->setObjectName("previousBytesButton");
    nextBytes_ = new QPushButton("下一页", hexPager_);
    nextBytes_->setObjectName("nextBytesButton");
    byteRange_ = new QLabel(hexPager_);
    byteRange_->setObjectName("byteRangeLabel");
    pagerLayout->addWidget(previousBytes_);
    pagerLayout->addWidget(byteRange_, 1);
    pagerLayout->addWidget(nextBytes_);
    byteLayout->addWidget(hexPager_);
    hexPager_->hide();
    panel("原始字节", bytePanel, detailSplit);
    hex_->setFont(style::dataFont());
    hex_->setPlaceholderText(i18n::text("选择数据包以查看字段和字节"));
    detailSplit->setSizes({560, 650});
    lowerLayout->addWidget(detailSplit, 1);
    vertical->addWidget(table_);
    vertical->addWidget(lower);
    vertical->setSizes({400, 300});
    layout->addWidget(vertical, 1);
    chart_ = new TrafficChart(root);
    chart_->setObjectName("trafficChart");
    chartPanel_ = panel("统计", chart_, root);
    chartPanel_->setMaximumHeight(130);
    chartPanel_->hide();
    layout->addWidget(chartPanel_);
    connect(statistics_, &QCheckBox::toggled, chartPanel_, &QWidget::setVisible);
    diagnosticPanel_ = new QWidget(root);
    diagnosticPanel_->setObjectName("diagnosticPanel");
    auto *diagnosticLayout = new QGridLayout(diagnosticPanel_);
    diagnosticLayout->setContentsMargins(style::margin, 6, style::margin, 6);
    diagnosticLayout->setHorizontalSpacing(12);
    const QStringList captions = {"捕获",     "解析",     "缓存",     "显示",
                                  "覆盖",     "队列丢弃", "驱动丢包", "异常",
                                  "缓存占用", "队列占用", "导出引用", "详情占用"};
    const QStringList keys = {"Received",    "Parsed",       "Retained",      "Displayed",
                              "Overwritten", "QueueDropped", "DriverDropped", "Malformed",
                              "CacheBytes",  "QueueBytes",   "ExportBytes",   "DetailBytes"};
    for (qsizetype i = 0; i < captions.size(); ++i) {
        auto *caption = new QLabel(captions[i], diagnosticPanel_);
        auto *value = new QLabel("0", diagnosticPanel_);
        value->setObjectName("diagnostic" + keys[i]);
        value->setFont(style::dataFont());
        diagnosticValues_.append(value);
        diagnosticLayout->addWidget(caption, static_cast<int>(i / 3), static_cast<int>(i % 3) * 2);
        diagnosticLayout->addWidget(value, static_cast<int>(i / 3),
                                    static_cast<int>(i % 3) * 2 + 1);
    }
    layout->addWidget(diagnosticPanel_);
    diagnosticPanel_->hide();
    auto *pendingCaption = new QLabel("Pending analysis", diagnosticPanel_);
    analysisPending_ = new QLabel("0", diagnosticPanel_);
    analysisPending_->setObjectName("analysisPending");
    diagnosticLayout->addWidget(pendingCaption, 4, 0);
    diagnosticLayout->addWidget(analysisPending_, 4, 1);
    auto *incompleteCaption = new QLabel("Incomplete analysis", diagnosticPanel_);
    analysisIncomplete_ = new QLabel("0", diagnosticPanel_);
    analysisIncomplete_->setObjectName("analysisIncomplete");
    diagnosticLayout->addWidget(incompleteCaption, 4, 2);
    diagnosticLayout->addWidget(analysisIncomplete_, 4, 3);
    const QStringList analysisCaptions = {"分析完成", "未完整",   "资源受限",
                                          "缺少密钥", "不支持的", "认证失败"};
    for (int i = 0; i < 6; ++i) {
        auto *caption = new QLabel(analysisCaptions[i], diagnosticPanel_);
        analysisStates_[i] = new QLabel("0", diagnosticPanel_);
        analysisStates_[i]->setObjectName("analysisState" + QString::number(i + 1));
        diagnosticLayout->addWidget(caption, 5 + i / 3, (i % 3) * 2);
        diagnosticLayout->addWidget(analysisStates_[i], 5 + i / 3, (i % 3) * 2 + 1);
    }
    setCentralWidget(root);
    statusBar()->setSizeGripEnabled(false);
    statusBar()->setMinimumHeight(30);
    status_ = new QLabel(this);
    status_->setObjectName("captureStatus");
    status_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    statusBar()->addWidget(status_, 1);
    exportLabel_ = new QLabel(this);
    exportLabel_->setObjectName("exportProgress");
    statusBar()->addPermanentWidget(exportLabel_);
    recordingLabel_ = new QLabel(this);
    recordingLabel_->setObjectName("recordingStatus");
    statusBar()->addPermanentWidget(recordingLabel_);
    auto counter = [&](const QString &caption, const QString &key) {
        statusBar()->addPermanentWidget(new QLabel(caption, this));
        auto *value = new QLabel("0", this);
        value->setObjectName(key);
        value->setMinimumWidth(28);
        statusBar()->addPermanentWidget(value);
        return value;
    };
    capturedLabel_ = counter("捕获", "capturedCount");
    displayedLabel_ = counter("显示", "displayedCount");
    droppedLabel_ = counter("队列丢弃", "droppedCount");
    diagnostics_ = new QPushButton("诊断", this);
    diagnostics_->setObjectName("diagnosticsToggle");
    diagnostics_->setCheckable(true);
    icons::bind(diagnostics_, icons::Id::Diagnostic);
    icons::bind(apply_, icons::Id::Filter);
    icons::bind(clear_, icons::Id::Close);
    statusBar()->addPermanentWidget(diagnostics_);
    connect(diagnostics_, &QPushButton::toggled, diagnosticPanel_, &QWidget::setVisible);
    sourceStatus_[0] = "就绪";
    sourceStatus_[1] = "就绪";
    connect(new QShortcut(QKeySequence::Open, this), &QShortcut::activated, open_,
            &QPushButton::click);
    connect(new QShortcut(QKeySequence::Save, this), &QShortcut::activated, save_,
            &QPushButton::click);
    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Return), this), &QShortcut::activated,
            this, [this] {
                if (!addressToggle_->isChecked())
                    addressToggle_->setChecked(true);
                applyFilter();
            });
    open_->setToolTip("打开  Ctrl+O");
    save_->setToolTip("保存  Ctrl+S");
    apply_->setToolTip("应用  Ctrl+Enter");
    connect(follow_, &QCheckBox::toggled, this, &MainWindow::updatePresentation);
    i18n::bind(this);
}
void MainWindow::arrangeFilters() {
    if (!filterLayout_)
        return;
    compactFilters_ = width() < 1180;
    for (auto *item : {macGroup_, ipGroup_, filterActions_})
        filterLayout_->removeWidget(item);
    filterLayout_->addWidget(macGroup_, 0, 0);
    filterLayout_->addWidget(ipGroup_, compactFilters_ ? 1 : 0, compactFilters_ ? 0 : 1);
    filterLayout_->addWidget(filterActions_, 0, compactFilters_ ? 1 : 2, compactFilters_ ? 2 : 1,
                             1);
    filterLayout_->setColumnStretch(0, 1);
    filterLayout_->setColumnStretch(1, compactFilters_ ? 0 : 2);
    filterLayout_->setColumnStretch(2, 0);
}
void MainWindow::resizeEvent(QResizeEvent *event) {
    QMainWindow::resizeEvent(event);
    if (filterLayout_ && compactFilters_ != (width() < 1180))
        arrangeFilters();
}
} // namespace etherscope
