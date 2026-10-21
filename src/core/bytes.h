#pragma once
#include <cstdint>
#include <span>
#include <stdexcept>

namespace etherscope {
// All lengths are bytes. Subtraction avoids overflow on untrusted offsets.
inline bool containsBytes(std::size_t size, std::size_t offset, std::size_t length) {
    return offset <= size && length <= size - offset;
}
class ByteView {
  public:
    explicit ByteView(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
    std::span<const std::uint8_t> slice(std::size_t offset, std::size_t length) const {
        if (!containsBytes(bytes_.size(), offset, length))
            throw std::runtime_error("Truncated data");
        return bytes_.subspan(offset, length);
    }
    std::uint64_t integer(std::size_t offset, unsigned width, bool little = false) const {
        if (width > 8)
            throw std::runtime_error("Invalid integer width");
        const auto value = slice(offset, width);
        std::uint64_t result = 0;
        for (unsigned i = 0; i < width; ++i)
            result = (result << 8) | value[little ? width - 1 - i : i];
        return result;
    }

  private:
    std::span<const std::uint8_t> bytes_;
};
} // namespace etherscope
