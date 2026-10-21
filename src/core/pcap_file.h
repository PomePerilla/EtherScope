#pragma once
#include "core/packet.h"
#include <filesystem>
#include <fstream>
#include <ostream>
#include <span>

namespace etherscope {
class PcapReader {
public:
    explicit PcapReader(const std::filesystem::path& path);
    std::optional<RawPacket> next();
    std::uint32_t linkType() const { return linkType_; }
private:
    std::ifstream stream_;
    bool little_{true},nano_{};
    std::uint32_t snapLength_{},linkType_{};
    std::uint32_t number(const std::uint8_t* p) const;
};
void writePcap(std::ostream& stream,std::span<const Packet* const> packets);
}
