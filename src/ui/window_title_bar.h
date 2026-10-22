#pragma once
#include <QWidget>

class QAbstractButton;
class QMouseEvent;
class QContextMenuEvent;

namespace etherscope {
class WindowTitleBar final : public QWidget {
  public:
    explicit WindowTitleBar(QWidget *window, QWidget *parent = nullptr);
    bool isDragArea(const QPoint &windowPosition) const;

  protected:
    bool eventFilter(QObject *watched, QEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseDoubleClickEvent(QMouseEvent *event) override;
    void contextMenuEvent(QContextMenuEvent *event) override;

  private:
    QWidget *window_;
    QAbstractButton *minimize_{}, *maximize_{}, *close_{};
    void refresh();
    void toggleMaximized();
};
} // namespace etherscope
