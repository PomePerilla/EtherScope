#include "core/capture_file.h"
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <cstdlib>
#include <map>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *bytes, std::size_t size) {
    if (size > 65535)
        return 0;
    struct Temp {
        std::filesystem::path path =
            std::filesystem::temp_directory_path() /
            ("etherscope-file-fuzz-" + std::to_string(std::random_device{}()));
        ~Temp() {
            std::error_code error;
            std::filesystem::remove(path, error);
        }
    };
    static Temp file, roundtrip;
    bool serialized = false;
    try {
        std::ofstream stream(file.path, std::ios::binary | std::ios::trunc);
        stream.write(reinterpret_cast<const char *>(bytes), static_cast<std::streamsize>(size));
        stream.close();
        etherscope::CaptureReader reader(file.path);
        std::vector<etherscope::RawPacket> packets;
        for (unsigned i = 0; i < 4096; ++i) {
            auto packet = reader.next();
            if (!packet)
                break;
            packets.push_back(std::move(*packet));
        }
        std::vector<const etherscope::RawPacket *> descriptors;
        for (const auto &packet : packets)
            descriptors.push_back(&packet);
        std::ostringstream output;
        etherscope::CaptureWriter writer(output, etherscope::CaptureFormat::Pcapng, descriptors);
        for (const auto &packet : packets)
            writer.write(packet);
        serialized = true;
        const auto data = output.str();
        std::ofstream target(roundtrip.path, std::ios::binary | std::ios::trunc);
        target.write(data.data(), static_cast<std::streamsize>(data.size()));
        target.close();
        etherscope::CaptureReader actual(roundtrip.path);
        std::map<std::uint32_t, std::uint32_t> interfaces;
        for (const auto &packet : packets) {
            const auto restored = actual.next();
            if (!restored || restored->bytes != packet.bytes ||
                restored->linkType != packet.linkType ||
                restored->originalLength != packet.originalLength ||
                restored->timestampValid != packet.timestampValid ||
                (packet.timestampValid && restored->timestampNs != packet.timestampNs))
                std::abort();
            const auto [it, inserted] =
                interfaces.emplace(packet.interfaceId, restored->interfaceId);
            if (!inserted && it->second != restored->interfaceId)
                std::abort();
        }
        if (actual.next())
            std::abort();
    } catch (const std::exception &) {
        if (serialized)
            std::abort();
    }
    return 0;
}
