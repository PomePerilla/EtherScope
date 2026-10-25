#pragma once
#include "core/session.h"
#include "ui/source_context.h"
#include "core/application.h"
#include "capture/stream.h"
#include <QWidget>
class QTableView;
class QTreeWidget;
class QLabel;
class QPushButton;
class QTabWidget;
class QKeyEvent;
namespace etherscope {
class TcpTableModel;
class StreamPane;
class ApplicationIndex;
class TcpPanel final : public QWidget {
    Q_OBJECT
  public:
    explicit TcpPanel(QWidget *parent = nullptr, StreamDecoder decoder = {});
    void refresh(const SessionStore &store, const QString &mode);
    void selectConversation(std::uint64_t id);
    void showError(const QString &error);
    bool streamBusy() const;
    void setApplicationIndex(const ApplicationIndex *index);
    void invalidate();
    void setSourceContext(SourceContext context);
    void setNavigationEnabled(bool enabled);
    std::uint64_t selectedConversation() const { return selectedId(); }
  signals:
    void workChanged();
    void closed();
    void analysisHelpRequested(etherscope::AnalysisStatus status);
    void expressionRequested(const QString &predicate, bool unique, etherscope::SourceContext context);
    void filterRequested(quint64 id, quint64 generation, const etherscope::SessionStore *store);
    void locateRequested(quint64 packetId, quint64 generation,
                         const etherscope::SessionStore *store);

  protected:
    void closeEvent(QCloseEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;

  private:
    const SessionStore *store_{};
    std::uint64_t generation_{}, revision_{};
    bool navigationEnabled_{true};
    bool refreshing_{}, selectFirst_{true}, closing_{}, streamExpanded_{};
    TcpTableModel *model_{};
    QTableView *table_{};
    QTreeWidget *events_{};
    StreamPane *stream_{};
    QTabWidget *tabs_{};
    QPushButton *streamButton_{};
    QPushButton *filter_{}, *locate_{};
    QLabel *mode_{}, *count_{}, *overwritten_{}, *skipped_{}, *memory_{};
    QLabel *error_{};
    std::array<QLabel *, 8> metrics_{};
    std::uint64_t selectedId() const;
    void renderSelection();
    void locate();
};
} // namespace etherscope
