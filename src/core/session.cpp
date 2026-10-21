#include "core/session.h"
#include <stdexcept>

namespace etherscope {
SessionStore::SessionStore(std::size_t maxPackets,std::size_t maxBytes,std::size_t maxEstimatedBytes):maxPackets_(maxPackets),maxBytes_(maxBytes),maxEstimatedBytes_(maxEstimatedBytes) {
    if(!maxPackets || !maxBytes || !maxEstimatedBytes) throw std::invalid_argument("Session limits must be positive");
}
void SessionStore::append(Packet packet) {
    ++stats_.received; stats_.wireBytes+=packet.raw.originalLength; ++stats_.protocols[packet.protocol];
    if(!packet.error.empty()) ++stats_.malformed;
    packet.id=nextId_++;
    tcp_.observe(packet);
    const auto n=packet.raw.bytes.size();
    packet.estimatedBytes=estimatePacketBytes(packet);const auto footprint=packet.estimatedBytes;
    if(n>maxBytes_ || footprint>maxEstimatedBytes_) { ++stats_.overwritten; return; }
    while(!packets_.empty() && (packets_.size()>=maxPackets_ || rawBytes_>maxBytes_-n || estimatedBytes_>maxEstimatedBytes_-footprint)) {
        rawBytes_-=packets_.front()->raw.bytes.size();estimatedBytes_-=packets_.front()->estimatedBytes;packets_.pop_front();++stats_.overwritten;
    }
    rawBytes_+=n;estimatedBytes_+=footprint;packets_.push_back(std::make_shared<Packet>(std::move(packet)));
}
void SessionStore::clear() { packets_.clear();rawBytes_=0;estimatedBytes_=0;nextId_=1;stats_={};tcp_.clear(); }
}
