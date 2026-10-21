#pragma once
#include <QPushButton>

namespace etherscope {
class FilterChip final : public QPushButton {
  public:
    explicit FilterChip(QWidget *parent = nullptr);
    void setCondition(const QString &text);
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

  protected:
    void resizeEvent(QResizeEvent *event) override;

  private:
    QString condition_;
    void updateText();
};
} // namespace etherscope
