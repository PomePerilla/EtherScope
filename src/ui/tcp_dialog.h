#pragma once
#include "core/session.h"
#include "capture/stream.h"
#include <QDialog>
class QTableView;
class QTreeWidget;
class QLabel;
class QPushButton;
class QTabWidget;
namespace etherscope {
class TcpTableModel;
class StreamPane;
class TcpDialog final:public QDialog {
    Q_OBJECT
public:
    explicit TcpDialog(QWidget* parent=nullptr,StreamDecoder decoder={});
    void refresh(const SessionStore& store,const QString& mode);
    void selectConversation(std::uint64_t id);
    void showError(const QString& error);
    bool streamBusy() const;
    void reject() override;
signals:
    void workChanged();
    void filterRequested(quint64 id,quint64 generation,const etherscope::SessionStore* store);
    void locateRequested(quint64 packetId,quint64 generation,const etherscope::SessionStore* store);
protected:
    void closeEvent(QCloseEvent* event) override;
private:
    const SessionStore* store_{};
    std::uint64_t generation_{},revision_{};
    bool refreshing_{},selectFirst_{true},closing_{},streamExpanded_{};
    TcpTableModel* model_{};
    QTableView* table_{};
    QTreeWidget* events_{};
    StreamPane* stream_{};
    QTabWidget* tabs_{};
    QPushButton* streamButton_{};
    QPushButton *filter_{},*locate_{};
    QLabel *mode_{},*count_{},*overwritten_{},*skipped_{},*memory_{};
    QLabel* error_{};
    std::array<QLabel*,8> metrics_{};
    std::uint64_t selectedId() const;
    void renderSelection();
    void locate();
};
}
