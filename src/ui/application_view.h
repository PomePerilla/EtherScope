#pragma once
#include "core/application.h"
#include "ui/source_context.h"
#include <QWidget>
#include <QTimer>
class QComboBox;
class QTreeWidget;
class QTreeWidgetItem;
class QPlainTextEdit;
class QLabel;
class QTextEdit;
class QPushButton;
class QSplitter;
class QResizeEvent;
namespace etherscope {
class ApplicationView final : public QWidget {
    Q_OBJECT
  public:
    explicit ApplicationView(QWidget *parent = nullptr);
    ~ApplicationView() override;
    void setNavigationEnabled(bool enabled);
    void setSourceContext(SourceContext context) { context_ = context; }
    void setResults(std::vector<std::shared_ptr<const ApplicationResult>> results);
  signals:
    void locateRequested(quint64 packet);
    void analysisHelpRequested(etherscope::AnalysisStatus status);
    void filterRequested(const QString &predicate, bool unique, etherscope::SourceContext context);
  protected:
    void resizeEvent(QResizeEvent *event) override;

  private:
    std::vector<std::shared_ptr<const ApplicationResult>> results_;
    std::vector<const ApplicationMessage *> messages_;
    const ApplicationMessage *selected_{};
    QTreeWidget *list_{}, *fields_{};
    QComboBox *sources_{}, *packets_{};
    QPlainTextEdit *bytes_{};
    QLabel *page_{};
    QPushButton *state_{}, *locate_{}, *fieldHelpToggle_{}, *nextStep_{}, *previous_{}, *next_{};
    QTextEdit *fieldHelp_{}, *statusHelp_{};
    QWidget *fieldHelpArea_{}, *statusHelpArea_{}, *statusHelpPanel_{}, *pager_{};
    QSplitter *lower_{};
    bool navigationEnabled_{true};
    SourceContext context_;
    AnalysisStatus status_{AnalysisStatus::Pending};
    void updateHelp();
    QTimer fillTimer_;
    std::size_t filled_{}, fieldFilled_{}, offset_{}, preferredMessage_{};
    int restoreField_{-1};
    void rebuild();
    void fill();
    void select();
    void page(std::size_t offset);
    void highlightField();
};
} // namespace etherscope
