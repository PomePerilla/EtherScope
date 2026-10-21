#include "core/tcp_conversations.h"
#include <algorithm>
#include <stdexcept>

namespace etherscope {
namespace {
constexpr std::uint8_t fin=1,syn=2,rst=4,ack=16;
TcpEndpoint endpoint(const Packet& packet,bool source) {
    TcpEndpoint result;result.port=source?packet.tcp->sourcePort:packet.tcp->destinationPort;
    const auto& v6=source?packet.sourceIpv6:packet.destinationIpv6;
    const auto& v4=source?packet.sourceIp:packet.destinationIp;
    result.ipv6=v6.has_value();
    if(v6)result.address=*v6;else if(v4)std::copy(v4->begin(),v4->end(),result.address.begin());
    return result;
}
std::optional<std::uint64_t> elapsed(std::int64_t begin,std::int64_t end) {
    if(end<begin)return {};
    return static_cast<std::uint64_t>(end)-static_cast<std::uint64_t>(begin);
}
void event(TcpConversation& item,const Packet& packet,unsigned direction,TcpEventKind kind) {
    auto index=(item.eventStart+item.eventCount)%item.eventLimit;
    if(item.eventCount==item.eventLimit){item.eventStart=(item.eventStart+1)%item.eventLimit;++item.eventsOverwritten;}
    else ++item.eventCount;
    item.events[index]={packet.id,packet.raw.timestampNs,packet.tcp->sequence,packet.tcp->acknowledgment,kind,direction,packet.raw.timestampValid};
}
void analyze(TcpConversation& item,const Packet& packet,unsigned direction) {
    const auto& t=*packet.tcp;const auto other=1u-direction;const bool pureSyn=(t.flags&(syn|ack))==syn;
    if(pureSyn) {
        auto& seen=item.syn[direction];
        if(seen.seen)++item.synRepeats;
        else {
            seen={t.sequence,t.sequence+1+t.payloadLength,packet.raw.timestampNs,true,packet.raw.timestampValid};
            if(item.initiator<0)item.initiator=static_cast<int>(direction);else item.simultaneousOpen=true;
        }
        event(item,packet,direction,TcpEventKind::Syn);
    } else if((t.flags&(syn|ack))==(syn|ack)) {
        if(item.initiator>=0 && static_cast<unsigned>(item.initiator)==other && !item.simultaneousOpen
            && t.acknowledgment==item.syn[other].next && !item.synAck.seen) {
            item.synAck={t.sequence,t.sequence+1+t.payloadLength,packet.raw.timestampNs,true,packet.raw.timestampValid};
            if(item.syn[other].timestampValid && packet.raw.timestampValid)item.synAckNs=elapsed(item.syn[other].timestampNs,packet.raw.timestampNs);
        }
        event(item,packet,direction,TcpEventKind::SynAck);
    } else if((t.flags&ack) && !(t.flags&rst) && item.initiator==static_cast<int>(direction)
        && item.synAck.seen && !item.simultaneousOpen && !item.handshakeSeen
        && t.sequence==item.syn[direction].next && t.acknowledgment==item.synAck.next) {
        item.handshakeSeen=true;
        if(item.synAckNs && packet.raw.timestampValid && packet.raw.timestampNs>=item.synAck.timestampNs)
            item.handshakeNs=elapsed(item.syn[direction].timestampNs,packet.raw.timestampNs);
        event(item,packet,direction,TcpEventKind::Handshake);
    }
    if(t.flags&rst){++item.resets;event(item,packet,direction,TcpEventKind::Reset);}
    else {
        if((t.flags&ack) && item.finNext[other] && !item.finAcked[other]
            && std::uint32_t(t.acknowledgment-*item.finNext[other])<0x80000000u) {
            item.finAcked[other]=true;event(item,packet,direction,TcpEventKind::FinAcknowledged);
        }
        if(t.flags&fin) {
            if(!item.finNext[direction])item.finNext[direction]=t.sequence+t.payloadLength+1;
            event(item,packet,direction,TcpEventKind::Fin);
        }
    }
    if(item.resets)item.state=TcpState::Reset;
    else if(item.finAcked[0] && item.finAcked[1])item.state=TcpState::Closed;
    else if(item.finNext[0] || item.finNext[1])item.state=TcpState::Closing;
    else if(item.handshakeSeen)item.state=TcpState::Established;
    else if(item.syn[0].seen || item.syn[1].seen || item.synAck.seen)item.state=TcpState::Handshake;
}
}
std::string formatEndpointAddress(const TcpEndpoint& endpoint) {
    if(endpoint.ipv6)return formatIpv6(endpoint.address);
    std::array<std::uint8_t,4> v4{};std::copy_n(endpoint.address.begin(),4,v4.begin());return formatIp(v4);
}
TcpConversations::TcpConversations(std::size_t maximum):maximum_(maximum) {
    if(!maximum || maximum>connectionLimit)throw std::invalid_argument("TCP conversation limit must be 1-1024");
}
void TcpConversations::observe(Packet& packet) {
    packet.tcpConversationId=0;
    if(packet.protocol!="TCP")return;
    ++revision_;
    if(!packet.tcp || !packet.tcp->completeSegment || !packet.error.empty()
        || !((packet.sourceIp && packet.destinationIp) || (packet.sourceIpv6 && packet.destinationIpv6))
        || ((packet.tcp->flags&syn) && (packet.tcp->flags&(fin|rst))) || ((packet.tcp->flags&fin) && (packet.tcp->flags&rst))) {++skipped_;return;}
    auto source=endpoint(packet,true),destination=endpoint(packet,false);
    if(source==destination){++skipped_;return;}
    const unsigned direction=source<destination?0:1;
    TcpKey key{direction?destination:source,direction?source:destination,packet.vlanId,packet.raw.interfaceId};
    auto current=current_.find(key);const auto& tcp=*packet.tcp;const bool pureSyn=(tcp.flags&(syn|ack))==syn;
    bool fresh=current==current_.end();
    if(!fresh && pureSyn) {
        const auto& item=*current->second;
        fresh=item.resets || item.finNext[0] || item.finNext[1]
            || (item.initiator<0) || (item.syn[direction].seen && item.syn[direction].sequence!=tcp.sequence);
    }
    if(fresh) {
        while(items_.size()>=maximum_) {
            auto oldest=current_.find(items_.front().key);
            if(oldest!=current_.end() && oldest->second==items_.begin())current_.erase(oldest);
            items_.pop_front();++overwritten_;
        }
        TcpConversation item;item.id=nextId_++;item.key=key;
        items_.push_back(std::move(item));current=current_.insert_or_assign(key,std::prev(items_.end())).first;
    }
    auto it=current->second;items_.splice(items_.end(),items_,it);auto& item=*it;
    ++item.packets[direction];item.wireBytes[direction]+=packet.raw.originalLength;item.payloadBytes[direction]+=tcp.payloadLength;
    if(packet.raw.timestampValid){if(!item.hasTimestamps)item.firstNs=item.lastNs=packet.raw.timestampNs;else {item.firstNs=std::min(item.firstNs,packet.raw.timestampNs);item.lastNs=std::max(item.lastNs,packet.raw.timestampNs);}item.hasTimestamps=true;}
    analyze(item,packet,direction);packet.tcpConversationId=item.id;
}
void TcpConversations::clear() {items_.clear();current_.clear();nextId_=1;overwritten_=skipped_=0;++revision_;++generation_;}
const TcpConversation* TcpConversations::find(std::uint64_t id) const {
    const auto it=std::find_if(items_.begin(),items_.end(),[id](const auto& value){return value.id==id;});
    return it==items_.end()?nullptr:&*it;
}
std::size_t TcpConversations::estimatedBytes() const {
    return sizeof(*this)+items_.size()*(sizeof(TcpConversation)+2*sizeof(void*))
        +current_.size()*(sizeof(decltype(current_)::value_type)+4*sizeof(void*));
}
}
