#include "fixtures.h"
#include <filesystem>
#include <fstream>
#include <string_view>

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3)
        return 2;
    const std::filesystem::path directory(argv[1]);
    std::filesystem::create_directories(directory);
    if (argc == 3) {
        if (std::string_view(argv[2]) != "--stream")
            return 2;
        std::vector<std::uint8_t> input = {100, 0, 0, 0, 1};
        for (auto raw : etherscope::fixtures::tcpStreamSamples()) {
            const auto packet = etherscope::decodeSummary(std::move(raw));
            const auto &tcp = *packet.tcp;
            input.push_back(tcp.sourcePort == 443 ? 1 : 0);
            const auto relative = std::uint32_t(tcp.sequence - 100);
            for (unsigned shift = 0; shift < 32; shift += 8)
                input.push_back(static_cast<std::uint8_t>(relative >> shift));
            input.push_back(tcp.flags);
            input.push_back(static_cast<std::uint8_t>(tcp.payloadLength));
            input.insert(input.end(), packet.raw.bytes.begin() + tcp.payloadOffset,
                         packet.raw.bytes.end());
        }
        for (std::size_t i = 0; i < input.size(); ++i) {
            auto copy = input;
            if (i % 2 == 0)
                copy.resize(i);
            else
                copy[i] ^= 255;
            std::ofstream file(directory / std::to_string(i), std::ios::binary);
            file.write(reinterpret_cast<const char *>(copy.data()),
                       static_cast<std::streamsize>(copy.size()));
            if (!file)
                return 1;
        }
        std::ofstream file(directory / "full", std::ios::binary);
        file.write(reinterpret_cast<const char *>(input.data()),
                   static_cast<std::streamsize>(input.size()));
        return file ? 0 : 1;
    }
    auto raws = etherscope::fixtures::samples();
    for (auto list : {etherscope::fixtures::ipv6Samples(), etherscope::fixtures::analysisSamples(),
                      etherscope::fixtures::tcpConversationSamples()})
        raws.insert(raws.end(), list.begin(), list.end());
    std::vector<std::uint8_t> dense(24, 0);
    dense[0] = 135;
    for (int i = 0; i < 3000; ++i)
        dense.insert(dense.end(), {1, 1, 0, 1, 2, 3, 4, 5});
    raws.push_back(etherscope::fixtures::ipv6(58, dense, 255));
    for (auto raw :
         {etherscope::fixtures::samples().front(), etherscope::fixtures::ipv6Samples().front()}) {
        const auto family = raw.bytes[14] >> 4 == 6 ? 24 : 2;
        raw.bytes.erase(raw.bytes.begin(), raw.bytes.begin() + 14);
        raw.bytes.insert(raw.bytes.begin(), 4, 0);
        raw.bytes[0] = static_cast<std::uint8_t>(family);
        raw.linkType = 0;
        raw.originalLength = static_cast<std::uint32_t>(raw.bytes.size());
        raws.push_back(std::move(raw));
    }
    std::size_t number = 0;
    for (const auto &raw : raws)
        for (int kind = 0; kind < 3; ++kind) {
            auto bytes = raw.bytes;
            if (kind == 1)
                bytes.resize(bytes.size() / 2);
            if (kind == 2 && !bytes.empty())
                bytes.back() ^= 255;
            std::ofstream file(directory / std::to_string(number++), std::ios::binary);
            file.put(raw.linkType == 0 ? 2 : 1);
            for (unsigned shift = 0; shift < 32; shift += 8)
                file.put(static_cast<char>(raw.originalLength >> shift));
            file.write(reinterpret_cast<const char *>(bytes.data()),
                       static_cast<std::streamsize>(bytes.size()));
            if (!file)
                return 1;
        }
}
