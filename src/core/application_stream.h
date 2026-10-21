#pragma once
#include "core/tls.h"

namespace etherscope {
// append() accepts new contiguous bytes only. Published messages own immutable ranges.
class Http1Stream {
  public:
    Http1Stream();
    ~Http1Stream();
    ApplicationResult append(const std::array<ApplicationInput, 2> &, std::stop_token = {});
    void prune(std::uint64_t firstPacket);
    std::size_t estimatedBytes() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
class Http2Stream {
  public:
    Http2Stream();
    ~Http2Stream();
    ApplicationResult append(const std::array<ApplicationInput, 2> &, std::stop_token = {});
    void prune(std::uint64_t firstPacket);
    std::size_t estimatedBytes() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
class TlsStream {
  public:
    TlsStream();
    ~TlsStream();
    TlsResult append(const std::array<ApplicationInput, 2> &, const TlsKeyLog &,
                     std::stop_token = {});
    void prune(std::uint64_t firstPacket);
    std::size_t estimatedBytes() const;
    std::optional<TlsKeyLog::Random> clientRandom() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace etherscope
