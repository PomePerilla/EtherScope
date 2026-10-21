#pragma once
#include "core/session.h"
#include <QDialog>
class QTableView;
class QTreeWidget;
class QLabel;
class QPushButton;
namespace etherscope {
class TcpTableModel;
class TcpDialog final:public QDialog {
    Q_OBJECT
public:
    explicit TcpDialog(QWidget* parent=nullptr);
    void refresh(const SessionStore& store,const QString& mode);
    void selectConversation(std::uint64_t id);
    void showError(const QString& error);
signals:
    void filterRequested(quint64 id,quint64 generation,const etherscope::SessionStore* store);
    void locateRequested(quint64 packetId,quint64 generation,const etherscope::SessionStore* store);
private:
    const SessionStore* store_{};
    std::uint64_t generation_{},revision_{};
    bool refreshing_{};
    TcpTableModel* model_{};
    QTableView* table_{};
    QTreeWidget* events_{};
    QPushButton *filter_{},*locate_{};
    QLabel *mode_{},*count_{},*overwritten_{},*skipped_{},*memory_{};
    QLabel* error_{};
    std::array<QLabel*,8> metrics_{};
    std::uint64_t selectedId() const;
    void renderSelection();
    void locate();
};
}
