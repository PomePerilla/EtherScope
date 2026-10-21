#pragma once
#include "core/application.h"
#include "core/bytes.h"
#include <algorithm>
#include <limits>

namespace etherscope::detail {
class ApplicationBuffer {
  public:
    ApplicationInput data;
    std::uint64_t base{};
    ApplicationBuffer() : bytes_(std::make_shared<std::vector<std::uint8_t>>()) {
        data.bytes = bytes_;
    }
    void append(const ApplicationInput &input) {
        if (!input.bytes && !input.startKnown && !input.endKnown && !input.incomplete)
            return;
        data.direction = input.direction;
        data.source = input.source;
        data.startKnown |= input.startKnown;
        data.endKnown |= input.endKnown;
        data.incomplete |= input.incomplete;
        if (!input.bytes || input.bytes->empty())
            return;
        if (input.bytes->size() > streamDirectionLimit - bytes_->size())
            throw std::length_error("Application input limit reached");
        writable();
        const auto offset = bytes_->size();
        bytes_->insert(bytes_->end(), input.bytes->begin(), input.bytes->end());
        for (auto source : input.sources) {
            source.bufferOffset += offset;
            data.sources.push_back(source);
        }
        if (data.sources.size() > streamPieceLimit)
            throw std::length_error("Application source limit reached");
    }
    void consume(std::size_t count) {
        if (!count)
            return;
        writable();
        bytes_->erase(bytes_->begin(), bytes_->begin() + static_cast<std::ptrdiff_t>(count));
        base += count;
        for (auto it = data.sources.begin(); it != data.sources.end();) {
            const auto length = it->bufferLength ? it->bufferLength : it->length;
            if (it->bufferOffset + length <= count) {
                it = data.sources.erase(it);
            } else {
                const auto removed = count > it->bufferOffset ? count - it->bufferOffset : 0;
                if (data.source != DataSource::Decrypted) {
                    it->rawOffset += removed;
                    it->length -= removed;
                } else {
                    it->bufferLength = length - removed;
                }
                it->bufferOffset = it->bufferOffset + removed - count;
                ++it;
            }
        }
    }
    std::size_t size() const {
        return bytes_->size();
    }
    std::size_t estimatedBytes() const {
        return sizeof(*this) + bytes_->capacity() + data.sources.capacity() * sizeof(SourceSpan);
    }

  private:
    std::shared_ptr<std::vector<std::uint8_t>> bytes_;
    void writable() {
        // data.bytes is the buffer's second reference. Other readers require copy-on-write.
        if (bytes_.use_count() > 2) {
            bytes_ = std::make_shared<std::vector<std::uint8_t>>(*bytes_);
            data.bytes = bytes_;
        }
    }
};
inline void freezeMessage(ApplicationMessage &message, std::uint64_t base = 0) {
    if (!message.bytes)
        return;
    if (!message.streamOffset)
        message.streamOffset = base + message.offset;
    const auto offset = message.offset;
    if (!containsBytes(message.bytes->size(), offset, message.length))
        throw std::runtime_error("Invalid application message range");
    auto begin = offset, end = offset + message.length;
    for (const auto &field : message.fields) {
        if (!containsBytes(message.bytes->size(), field.offset, field.length))
            throw std::runtime_error("Invalid application field range");
        begin = std::min(begin, field.offset);
        end = std::max(end, field.offset + field.length);
    }
    message.bytes = std::make_shared<const std::vector<std::uint8_t>>(
        message.bytes->begin() + static_cast<std::ptrdiff_t>(begin),
        message.bytes->begin() + static_cast<std::ptrdiff_t>(end));
    message.offset -= begin;
    for (auto &field : message.fields)
        field.offset -= begin;
    for (auto &source : message.sources) {
        const auto logical = source.bufferLength ? source.bufferLength : source.length;
        const auto first = std::max(begin, source.bufferOffset);
        const auto last = std::min(end, source.bufferOffset + logical);
        if (first >= last) {
            source.bufferLength = 0;
            source.length = 0;
            source.bufferOffset = 0;
            continue;
        }
        if (message.source != DataSource::Decrypted) {
            source.rawOffset += first - source.bufferOffset;
            source.length = last - first;
        }
        source.bufferLength = last - first;
        source.bufferOffset = first - begin;
    }
    std::erase_if(message.sources, [](const auto &source) { return !source.length; });
}
inline void pruneMessages(ApplicationResult &result, std::uint64_t first) {
    if (!first)
        return;
    std::erase_if(result.messages, [first](const auto &message) {
        return !message.sources.empty() &&
               std::all_of(message.sources.begin(), message.sources.end(),
                           [first](const auto &source) { return source.packetId < first; });
    });
    result.estimatedBytes = estimateApplicationBytes(result);
}
// Expired messages are removed before accepting another complete message, not reparsed later.
inline std::size_t
appendStreamMessage(ApplicationResult &result, ApplicationMessage message,
                    std::uint64_t &droppedThrough,
                    std::size_t protectedFrom = std::numeric_limits<std::size_t>::max()) {
    std::size_t removed = 0, nodes = message.fields.size();
    for (const auto &existing : result.messages)
        nodes += existing.fields.size();
    result.messages.push_back(std::move(message));
    for (;;) {
        const auto bytes = estimateApplicationBytes(result);
        if (nodes <= maxPacketFields && result.messages.size() <= 1024 &&
            bytes <= applicationResultLimit) {
            result.estimatedBytes = bytes;
            break;
        }
        if (result.messages.size() == 1 || removed >= protectedFrom) {
            result.messages.pop_back();
            throw std::length_error("Application result limit reached");
        }
        droppedThrough = std::max<std::uint64_t>(droppedThrough, 1);
        for (const auto &source : result.messages.front().sources)
            droppedThrough = std::max(droppedThrough, source.packetId);
        nodes -= result.messages.front().fields.size();
        result.messages.erase(result.messages.begin());
        ++removed;
    }
    return removed;
}
} // namespace etherscope::detail
