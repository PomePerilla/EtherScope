#pragma once
#include "core/packet.h"
#include <filesystem>
#include <fstream>
#include <map>
#include <ostream>
#include <span>

namespace etherscope {
enum class CaptureFormat { Pcap, Pcapng };
inline constexpr std::uint32_t maxCaptureRecord = 16 * 1024 * 1024;
class CaptureReader {
  public:
    explicit CaptureReader(const std::filesystem::path &path);
    std::optional<RawPacket> next();
    CaptureFormat format() const {
        return format_;
    }
    std::uint32_t linkType() const {
        return linkType_;
    }

  private:
    struct Interface {
        std::uint32_t id{}, link{}, snap{};
        std::uint8_t resolution{6};
        std::int64_t offset{};
        std::shared_ptr<CaptureInterfaceInfo> info;
    };
    std::ifstream stream_;
    CaptureFormat format_{CaptureFormat::Pcap};
    bool little_{true}, nano_{};
    std::uint32_t snapLength_{}, linkType_{}, nextInterface_{};
    std::size_t metadataBytes_{};
    std::vector<Interface> interfaces_;
    void section(std::span<const std::uint8_t> body);
    std::optional<RawPacket> nextPcap();
    std::optional<RawPacket> nextPcapng();
};
// A writer belongs to one background I/O task. It never owns packet data.
class CaptureWriter {
  public:
    CaptureWriter(std::ostream &stream, CaptureFormat format,
                  std::span<const RawPacket *const> interfaces);
    void write(const RawPacket &packet);
    std::uint64_t bytesWritten() const {
        return bytes_;
    }

  private:
    struct Interface {
        std::uint32_t index, link, snap;
    };
    std::ostream &stream_;
    CaptureFormat format_;
    std::map<std::uint32_t, Interface> interfaces_;
    std::uint64_t bytes_{};
    void block(std::uint32_t type, std::span<const std::uint8_t> body);
    void output(std::span<const std::uint8_t> bytes);
};
void writeCapture(std::ostream &stream, std::span<const Packet *const> packets,
                  CaptureFormat format);
} // namespace etherscope
