#pragma once
#include "core/application.h"
#include "ui/source_context.h"
#include "ui/reading_history.h"
#include <QWidget>
#include <QTimer>
#include <QHash>
#include <optional>
class QComboBox;
class QTreeWidget;
class QTreeWidgetItem;
class QPlainTextEdit;
class QLabel;
class QTextEdit;
class QPushButton;
class QSplitter;
class QResizeEvent;
class QLayout;
namespace etherscope {
class FindBar;
class ApplicationView final : public QWidget {
    Q_OBJECT
  public:
    explicit ApplicationView(QWidget *parent = nullptr);
    ~ApplicationView() override;
    void setNavigationEnabled(bool enabled);
    bool updating() const { return updating_ || pendingResults_.has_value(); }
    enum class Scope { Packet, Conversation };
    void setSourceContext(SourceContext context);
    void setBinding(SourceContext context, Scope scope, std::uint64_t id, bool reset = false);
    void setResults(std::vector<std::shared_ptr<const ApplicationResult>> results);
  signals:
    void locateRequested(quint64 packet);
    void analysisHelpRequested(etherscope::AnalysisStatus status);
    void filterRequested(const QString &predicate, bool unique, etherscope::SourceContext context);
  protected:
    void resizeEvent(QResizeEvent *event) override;

  private:
    FindBar *find_{};
    ReadingHistory history_;
    QPushButton *back_{}, *forward_{};
    QVariantMap pendingReading_;
    std::optional<std::pair<std::size_t, std::size_t>> findByteRange_;
    void initializeFind(QLayout *bar);
    QVariantMap readingPosition() const;
    void rememberReading();
    void navigateReading(bool forward);
    void restoreReadingDetails();
    void updateReadingActions();
    std::vector<std::shared_ptr<const ApplicationResult>> results_;
    using Results = std::vector<std::shared_ptr<const ApplicationResult>>;
    struct MessageRow { QString key, base; const ApplicationMessage *message{}; };
    struct FieldRow { QString key; const ApplicationField *field{}; };
    std::optional<Results> pendingResults_;
    std::vector<MessageRow> messages_;
    std::vector<FieldRow> fieldRows_;
    QHash<QString, const ApplicationMessage *> messageByKey_;
    QHash<QString, int> messageCounts_;
    QHash<QString, const ApplicationField *> fieldByKey_;
    QHash<QString, QTreeWidgetItem *> messageItems_, fieldItems_;
    QString selectedKey_, fieldKey_;
    QStringList removals_;
    std::size_t rowCursor_{}, removeCursor_{};
    bool freshSelection_{}, updating_{}, firstSelection_{true}, lostSelection_{}, fieldDirty_{}, messagesDone_{};
    Scope scope_{Scope::Packet};
    std::uint64_t scopeId_{}, bindingEpoch_{};
    void resetPresentation();
    void beginUpdate();
    void prepareFields();
    void finishFields();
    void clearDetails();
    void syncPackets(bool preserve);
    bool menuTargetValid(quint64 epoch, const QString &message, const QString &field) const;
    const ApplicationMessage *selected_{};
    QTreeWidget *list_{}, *fields_{};
    QComboBox *sources_{}, *packets_{};
    QPlainTextEdit *bytes_{};
    QLabel *page_{}, *selectionHint_{};
    QPushButton *state_{}, *locate_{}, *fieldHelpToggle_{}, *nextStep_{}, *previous_{}, *next_{};
    QTextEdit *fieldHelp_{}, *statusHelp_{};
    QWidget *fieldHelpArea_{}, *statusHelpArea_{}, *statusHelpPanel_{}, *pager_{};
    QSplitter *lower_{};
    bool navigationEnabled_{true};
    SourceContext context_;
    AnalysisStatus status_{AnalysisStatus::Pending};
    void updateHelp();
    QTimer fillTimer_;
    std::size_t offset_{};
    void rebuild();
    void fill();
    void select();
    void page(std::size_t offset, bool preserve = false);
    void highlightField();
};
} // namespace etherscope
