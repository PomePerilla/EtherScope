#pragma once
#include "capture/stream.h"
#include "core/session.h"
#include "ui/source_context.h"
#include "core/application_index.h"
#include <QWidget>
class QLabel;
class QComboBox;
class QTableView;
class QPlainTextEdit;
class QPushButton;
class QTabWidget;
namespace etherscope {
class StreamTableModel;
class ApplicationView;
class StreamPane final : public QWidget {
    Q_OBJECT
  public:
    explicit StreamPane(QWidget *parent = nullptr, StreamDecoder decoder = {});
    void setSelection(const SessionStore *store, std::uint64_t id);
    void start();
    void cancel();
    void setNavigationEnabled(bool enabled);
    void setSourceContext(SourceContext context);
    bool busy() const {
        return service_.busy();
    }
    bool ready() const {
        return result_ != nullptr;
    }
    void setApplicationIndex(const ApplicationIndex *index);
  signals:
    void workChanged();
    void analysisHelpRequested(etherscope::AnalysisStatus status);
    void filterRequested(const QString &predicate, bool unique, etherscope::SourceContext context);
    void analysisFinished(quint64 request, bool success);
    void locateRequested(quint64 packetId);

  private:
    bool navigationEnabled_{true};
    StreamService service_;
    const ApplicationIndex *applicationIndex_{};
    ApplicationView *applicationView_{};
    const SessionStore *store_{};
    std::uint64_t conversation_{}, generation_{};
    quint64 request_{};
    std::shared_ptr<const TcpStreamResult> result_;
    QComboBox *direction_{};
    QLabel *phase_{}, *scope_{}, *prefix_{}, *limit_{}, *page_{};
    std::array<QLabel *, 8> metrics_{};
    QPushButton *start_{}, *cancel_{}, *previous_{}, *next_{}, *locate_{};
    QTableView *ranges_{}, *events_{};
    QPlainTextEdit *bytes_{};
    StreamTableModel *rangeModel_{}, *eventModel_{};
    QTabWidget *tabs_{};
    std::size_t pageStart_{};
    std::uint64_t pagePacketId_{};
    static constexpr std::size_t pageSize_ = 1024;
    void clearResult();
    void display();
    void displayRange();
    void displayPage();
};
} // namespace etherscope
