#pragma once
#include <QLayout>
#include <QWidget>
#include <algorithm>

namespace workbench {
// A wrapping row whose height follows the actual translated control sizes.
class FlowLayout final : public QLayout {
  public:
    explicit FlowLayout(QWidget *parent = nullptr, int spacing = 8) : QLayout(parent) {
        setContentsMargins(0, 0, 0, 0);
        setSpacing(spacing);
    }
    ~FlowLayout() override {
        while (auto *item = takeAt(0))
            delete item;
    }
    void addItem(QLayoutItem *item) override {
        items_.append(item);
        invalidate();
    }
    int count() const override {
        return int(items_.size());
    }
    QLayoutItem *itemAt(int i) const override {
        return items_.value(i);
    }
    QLayoutItem *takeAt(int i) override {
        return i >= 0 && i < count() ? items_.takeAt(i) : nullptr;
    }
    Qt::Orientations expandingDirections() const override {
        return {};
    }
    bool hasHeightForWidth() const override {
        return true;
    }
    int heightForWidth(int width) const override {
        return arrange(QRect(0, 0, width, 0), false);
    }
    QSize minimumSize() const override {
        QSize size;
        for (auto *item : items_)
            if (!item->isEmpty())
                size = size.expandedTo(item->minimumSize());
        return size;
    }
    QSize sizeHint() const override {
        int width = 0, height = 0;
        for (auto *item : items_)
            if (!item->isEmpty()) {
                if (width)
                    width += spacing();
                width += item->sizeHint().width();
                height = std::max(height, item->sizeHint().height());
            }
        return {width, height};
    }
    void setGeometry(const QRect &rect) override {
        QLayout::setGeometry(rect);
        arrange(rect, true);
    }

  private:
    QList<QLayoutItem *> items_;
    int arrange(const QRect &rect, bool apply) const {
        int x = rect.x(), y = rect.y(), row = 0;
        for (auto *item : items_) {
            if (item->isEmpty())
                continue;
            auto size = item->sizeHint();
            size.setWidth(std::min(size.width(), rect.width()));
            if (x > rect.x() && x + size.width() > rect.x() + rect.width()) {
                x = rect.x();
                y += row + spacing();
                row = 0;
            }
            if (apply)
                item->setGeometry(QRect(QPoint(x, y), size));
            x += size.width() + spacing();
            row = std::max(row, size.height());
        }
        return y - rect.y() + row;
    }
};
} // namespace workbench

