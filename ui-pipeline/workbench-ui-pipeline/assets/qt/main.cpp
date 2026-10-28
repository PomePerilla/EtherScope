#include "workbench_style.h"
#include "flow_layout.h"
#include <QApplication>
#include <QAction>
#include <QComboBox>
#include <QDockWidget>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QShortcut>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QTableView>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    app.setStyle("Fusion");
    const auto directory = QString::fromUtf8(WORKBENCH_THEME_DIR);
    if (!workbench::applyTheme(app, true, directory)) return 2;
    QMainWindow window;
    window.setWindowTitle("Workbench sample");
    window.setMinimumSize(900, 580);
    window.resize(1200, 760);
    auto *root = new QWidget(&window); root->setProperty("wbRole", "workspace");
    auto *layout = new QVBoxLayout(root); layout->setContentsMargins(0, 0, 0, 0); layout->setSpacing(0);
    auto *toolbar = new QWidget(root); toolbar->setProperty("wbRole", "bar");
    auto *flow = new workbench::FlowLayout(toolbar, 8);
    auto *source = new QComboBox(toolbar); source->addItems({"本地实验 / Local", "归档 / Archive"}); source->setMinimumWidth(160); flow->addWidget(source);
    auto *start = new QPushButton("开始", toolbar); start->setProperty("wbRole", "primary"); flow->addWidget(start);
    auto *stop = new QPushButton("停止", toolbar); stop->setEnabled(false); flow->addWidget(stop);
    auto *theme = new QPushButton("切换主题", toolbar); flow->addWidget(theme);
    auto *diagnostics = new QPushButton("诊断", toolbar); diagnostics->setCheckable(true); flow->addWidget(diagnostics);
    layout->addWidget(toolbar);
    auto *filters = new QWidget(root); filters->setProperty("wbRole", "bar"); auto *filterFlow = new workbench::FlowLayout(filters, 8);
    auto *input = new QLineEdit(filters); input->setPlaceholderText("名称筛选，Enter 应用"); input->setMinimumWidth(220); filterFlow->addWidget(input);
    auto *clear = new QPushButton("清除", filters); filterFlow->addWidget(clear); layout->addWidget(filters);
    auto *split = new QSplitter(Qt::Vertical, root); split->setHandleWidth(workbench::splitterHit);
    auto *table = new QTableView(split); table->setSelectionBehavior(QAbstractItemView::SelectRows); table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setAlternatingRowColors(true); table->setShowGrid(false); table->verticalHeader()->hide(); table->verticalHeader()->setDefaultSectionSize(workbench::rowHeight);
    auto *model = new QStandardItemModel(table); model->setHorizontalHeaderLabels({"编号", "时间", "名称", "读数", "状态"});
    for (int n = 0; n < 12; ++n) {
        QList<QStandardItem *> items;
        for (const auto &value : QStringList{QString("RUN-%1").arg(n + 1, 3, 10, QChar('0')), "14:26:00", QString("Sweep %1").arg(QChar('A' + n)), QString::number(122 + n * 2.375, 'f', 3) + " mV", "完成"}) items.append(new QStandardItem(value));
        items[0]->setFont(workbench::dataFont()); items[1]->setFont(workbench::dataFont()); items[3]->setFont(workbench::dataFont()); model->appendRow(items);
    }
    table->setModel(model); table->horizontalHeader()->setStretchLastSection(true); table->setColumnWidth(2, 240);
    auto *details = new QSplitter(Qt::Horizontal, split); details->setHandleWidth(workbench::splitterHit);
    auto *fields = new QTreeWidget(details); fields->setHeaderLabels({"字段", "值"}); fields->setColumnWidth(0, 150);
    auto *raw = new QPlainTextEdit(details); raw->setReadOnly(true); raw->setFont(workbench::dataFont());
    split->setSizes({400, 300}); details->setSizes({500, 600}); layout->addWidget(split, 1); window.setCentralWidget(root);
    auto *dock = new QDockWidget("诊断", &window); auto *metrics = new QLabel("数据概况\n保留 12 条\n\n分析\n完成 12\n\n资源\n演示数据", dock); metrics->setMargin(12); metrics->setAlignment(Qt::AlignTop); dock->setWidget(metrics); window.addDockWidget(Qt::RightDockWidgetArea, dock); dock->hide();
    auto *status = new QLabel("就绪", &window); window.statusBar()->addWidget(status, 1);
    QObject::connect(start, &QPushButton::clicked, &window, [=] { start->setEnabled(false); stop->setEnabled(true); status->setText("运行中"); });
    QObject::connect(stop, &QPushButton::clicked, &window, [=] { start->setEnabled(true); stop->setEnabled(false); status->setText("已停止，可重新开始"); });
    bool dark = true;
    QObject::connect(theme, &QPushButton::clicked, &window, [&] { dark = !dark; workbench::applyTheme(app, dark, directory); });
    QObject::connect(diagnostics, &QPushButton::toggled, dock, &QWidget::setVisible);
    QObject::connect(dock, &QDockWidget::visibilityChanged, diagnostics, &QPushButton::setChecked);
    auto apply = [=] { for (int n = 0; n < model->rowCount(); ++n) table->setRowHidden(n, !model->item(n, 2)->text().contains(input->text(), Qt::CaseInsensitive)); };
    QObject::connect(input, &QLineEdit::returnPressed, &window, apply);
    QObject::connect(clear, &QPushButton::clicked, &window, [=] { input->clear(); apply(); });
    QObject::connect(table->selectionModel(), &QItemSelectionModel::currentRowChanged, &window, [=](const QModelIndex &current) {
        fields->clear(); QStringList values;
        for (int n = 0; current.isValid() && n < model->columnCount(); ++n) {
            const auto name = model->headerData(n, Qt::Horizontal).toString(), value = model->index(current.row(), n).data().toString();
            new QTreeWidgetItem(fields, {name, value}); values.append(name + ": " + value);
        }
        raw->setPlainText(values.join('\n'));
    });
    table->setCurrentIndex(model->index(0, 0)); window.show();
    const auto args = app.arguments(); const auto smoke = args.indexOf("--smoke");
    if (smoke >= 0 && smoke + 1 < args.size()) {
        const auto output = args[smoke + 1]; QDir().mkpath(output);
        QTimer::singleShot(100, &window, [&, output] {
            QJsonArray checks; bool passed = true;
            auto check = [&](const QString &name, bool ok) { checks.append(QJsonObject{{"name", name}, {"passed", ok}}); passed &= ok; };
            check("selected details", fields->topLevelItemCount() == 5 && raw->toPlainText().contains("RUN-001"));
            input->setText("Sweep B"); apply(); check("filter", table->isRowHidden(0) && !table->isRowHidden(1)); clear->click();
            start->click(); check("start", !start->isEnabled() && stop->isEnabled()); stop->click(); check("stop", start->isEnabled() && !stop->isEnabled());
            for (bool light : {false, true}) {
                workbench::applyTheme(app, !light, directory);
                for (const auto size : {QSize(900, 580), QSize(1024, 768), QSize(1440, 900)}) {
                    window.resize(size); app.processEvents();
                    check(QString("table layout %1").arg(size.width()), root->rect().contains(QRect(table->mapTo(root, QPoint()), table->size())));
                    check(QString("toolbar layout %1").arg(size.width()), toolbar->rect().contains(diagnostics->geometry()));
                    check("screenshot", window.grab().save(QDir(output).filePath(QString("qt-%1-%2.png").arg(light ? "light" : "dark").arg(size.width()))));
                }
            }
            diagnostics->click(); check("diagnostic", dock->isVisible()); dock->close(); check("diagnostic close", !diagnostics->isChecked());
            QFile report(QDir(output).filePath("qt-smoke.json"));
            if (!report.open(QIODevice::WriteOnly)) passed = false;
            else report.write(QJsonDocument(QJsonObject{{"passed", passed}, {"checks", checks}, {"qt_version", QT_VERSION_STR}}).toJson());
            app.exit(passed ? 0 : 1);
        });
    }
    return app.exec();
}
