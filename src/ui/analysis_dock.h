#pragma once
#include <QDockWidget>
#include <functional>
class QLabel;
class QPushButton;
namespace etherscope {
class AnalysisDock final : public QDockWidget {
    Q_OBJECT
  public:
    AnalysisDock(const QString &title, const QString &name, QWidget *parent);
    void setContent(QWidget *content);
    void setSource(const QString &source, const QString &identity = {});
    void setTabbed(bool tabbed);
    void showError(const QString &message);
    std::function<bool()> closeContent;
    bool preferredFloating{}, automaticFloating{}, initialized{};
    Qt::DockWidgetArea preferredArea{Qt::RightDockWidgetArea};
  signals:
    void rebindRequested();
  protected:
    void closeEvent(QCloseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
  private:
    QWidget *body_{}, *header_{};
    QLabel *title_{}, *source_{}, *identity_{}, *error_{};
    QPushButton *float_{}, *close_{};
    QString sourceText_;
    bool tabbed_{}, syncing_{};
    void syncHeader();
    void elideSource();
};
} // namespace etherscope
