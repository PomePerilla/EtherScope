#pragma once
#include "core/capture_file.h"

namespace etherscope {
// Compatibility entry point; both formats use the same detection path.
class PcapReader:public CaptureReader {
public:
    using CaptureReader::CaptureReader;
};
void writePcap(std::ostream& stream,std::span<const Packet* const> packets);
}
