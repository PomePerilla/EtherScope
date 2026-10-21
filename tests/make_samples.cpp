#include "fixtures.h"
#include "core/pcap_file.h"
#include <fstream>
#include <iostream>

int main(int argc, char **argv) {
    try {
        auto path = argc > 1 ? std::filesystem::path(argv[1])
                             : std::filesystem::path("synthetic-protocols.pcap");
        const auto kind = argc > 2 ? std::string_view(argv[2]) : std::string_view{};
        const auto raws =
            kind == "--stream"
                ? etherscope::fixtures::tcpStreamSamples()
                : (kind == "--tcp"
                       ? etherscope::fixtures::tcpConversationSamples()
                       : (kind == "--ipv6"
                              ? etherscope::fixtures::ipv6Samples()
                              : (kind == "--analysis" ? etherscope::fixtures::analysisSamples()
                                                      : etherscope::fixtures::samples())));
        std::vector<etherscope::Packet> packets;
        for (auto raw : raws)
            packets.push_back(etherscope::decodePacket(std::move(raw)));
        std::vector<const etherscope::Packet *> refs;
        for (const auto &p : packets)
            refs.push_back(&p);
        std::ofstream out(path, std::ios::binary);
        etherscope::writePcap(out, refs);
        std::cout << "Wrote " << packets.size()
                  << " SYNTHETIC packets. Not live capture evidence.\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
