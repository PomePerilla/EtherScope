#pragma once
#include <algorithm>
#include <array>
#include <cstdint>

// Saturated percentiles use the observed maximum, never an understated bound.
class BoundedSamples {
  public:
    void push_back(std::int64_t value) {
        value = std::max<std::int64_t>(0, value);
        ++buckets_[std::min<std::size_t>(static_cast<std::size_t>(value), buckets_.size() - 1)];
        ++count_;
        maximum_ = std::max(maximum_, value);
    }
    bool empty() const {
        return count_ == 0;
    }
    std::int64_t maximum() const {
        return maximum_;
    }
    std::int64_t percentile(unsigned percent) const {
        if (!count_)
            return 0;
        const auto target = std::min(count_ - 1, count_ * percent / 100);
        std::uint64_t seen = 0;
        for (std::size_t i = 0; i < buckets_.size(); ++i) {
            seen += buckets_[i];
            if (seen > target)
                return i + 1 == buckets_.size() ? maximum_ : static_cast<std::int64_t>(i);
        }
        return maximum_;
    }

  private:
    std::array<std::uint64_t, 8192> buckets_{};
    std::uint64_t count_{};
    std::int64_t maximum_{};
};
