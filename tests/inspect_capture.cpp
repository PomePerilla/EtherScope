#include "core/capture_file.h"
#include <fstream>
#include <iostream>

using namespace etherscope;
#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
#else
int main(int argc, char **argv) {
#endif
    if (argc < 2 || argc > 3)
        return 2;
    try {
        CaptureReader reader{std::filesystem::path(argv[1])};
        std::vector<RawPacket> packets;
        while (auto packet = reader.next()) {
            if (packets.size() >= 10000)
                throw std::length_error("Test record limit");
            packets.push_back(std::move(*packet));
        }
        for (const auto &packet : packets) {
            std::cout << packet.interfaceId << '\t' << packet.linkType << '\t'
                      << packet.timestampValid << '\t' << packet.timestampNs << '\t';
            for (auto byte : packet.bytes)
                std::cout << "0123456789abcdef"[byte >> 4] << "0123456789abcdef"[byte & 15];
            std::cout << '\n';
        }
        if (argc == 3) {
            std::vector<const RawPacket *> descriptors;
            for (const auto &packet : packets)
                descriptors.push_back(&packet);
            std::ofstream file(std::filesystem::path(argv[2]), std::ios::binary);
            CaptureWriter writer(file, CaptureFormat::Pcapng, descriptors);
            for (const auto &packet : packets)
                writer.write(packet);
        }
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
