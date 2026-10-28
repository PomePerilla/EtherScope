#pragma once
#include <QVariantMap>
#include <vector>
namespace etherscope {
// Metadata only. Each workspace validates its source generation when restoring.
class ReadingHistory {
  public:
    void clear() {
        back_.clear();
        forward_.clear();
    }
    void remember(const QVariantMap &position) {
        if (position.isEmpty())
            return;
        if (back_.empty() || back_.back() != position)
            back_.push_back(position);
        if (back_.size() > 50)
            back_.erase(back_.begin());
        forward_.clear();
    }
    bool canBack() const {
        return !back_.empty();
    }
    bool canForward() const {
        return !forward_.empty();
    }
    QVariantMap take(bool forward, const QVariantMap &current) {
        auto &from = forward ? forward_ : back_, &to = forward ? back_ : forward_;
        if (from.empty())
            return {};
        auto next = from.back();
        from.pop_back();
        if (!current.isEmpty())
            to.push_back(current);
        if (to.size() > 50)
            to.erase(to.begin());
        return next;
    }

  private:
    std::vector<QVariantMap> back_, forward_;
};
} // namespace etherscope
