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
    void setSource(const QString &source);
    void showError(const QString &message);
    std::function<bool()> closeContent;
    bool preferredFloating{}, automaticFloating{}, initialized{};
    Qt::DockWidgetArea preferredArea{Qt::RightDockWidgetArea};
  signals:
    void rebindRequested();
  protected:
    void closeEvent(QCloseEvent *event) override;
  private:
    QWidget *body_{};
    QLabel *source_{}, *error_{};
};
} // namespace etherscope
