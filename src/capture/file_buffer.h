#pragma once
#include "capture/export.h"
#include <QIODevice>
#include <algorithm>
#include <array>
#include <cstring>
#include <streambuf>
namespace etherscope {
// Shared 64 KiB buffer; short writes are retried, failures stay on the stream.
class FileBuffer final : public std::streambuf {
  public:
    FileBuffer(QIODevice &file, const ExportWriter &writer, std::function<void(quint64)> progress)
        : file_(file), writer_(writer), progress_(std::move(progress)) {
        setp(buffer_.data(), buffer_.data() + buffer_.size());
    }

  protected:
    int sync() override {
        const auto pending = pptr() - pbase();
        qint64 written = 0;
        while (written < pending) {
            const auto n = writer_ ? writer_(file_, pbase() + written, pending - written)
                                   : file_.write(pbase() + written, pending - written);
            if (n <= 0 || n > pending - written)
                return -1;
            written += n;
            bytes_ += static_cast<quint64>(n);
            progress_(bytes_);
        }
        pbump(-static_cast<int>(pending));
        return 0;
    }
    int_type overflow(int_type ch) override {
        if (sync() != 0)
            return traits_type::eof();
        if (!traits_type::eq_int_type(ch, traits_type::eof())) {
            *pptr() = traits_type::to_char_type(ch);
            pbump(1);
        }
        return traits_type::not_eof(ch);
    }
    std::streamsize xsputn(const char *data, std::streamsize count) override {
        std::streamsize copied = 0;
        while (copied < count) {
            if (pptr() == epptr() && sync() != 0)
                break;
            const auto n = std::min<std::streamsize>(epptr() - pptr(), count - copied);
            std::memcpy(pptr(), data + copied, static_cast<std::size_t>(n));
            pbump(static_cast<int>(n));
            copied += n;
        }
        return copied;
    }

  private:
    QIODevice &file_;
    const ExportWriter &writer_;
    std::function<void(quint64)> progress_;
    std::array<char, 64 * 1024> buffer_{};
    quint64 bytes_{};
};
} // namespace etherscope
