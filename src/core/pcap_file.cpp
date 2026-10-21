#include "core/pcap_file.h"
namespace etherscope {
void writePcap(std::ostream &stream, std::span<const Packet *const> packets) {
    writeCapture(stream, packets, CaptureFormat::Pcap);
}
} // namespace etherscope
