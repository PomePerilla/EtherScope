#include "core/filter.h"
#include "core/pcap_file.h"
#include "core/session.h"
#include "fixtures.h"
#include "parser_invariants.h"
#include <algorithm>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>

using namespace etherscope;
namespace {
int checks{};
void check(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
Packet packet(std::uint8_t flags,std::uint32_t seq,std::uint32_t ack=0,bool reverse=false,std::int64_t ms=0,bool v6=false) {
    auto raw=fixtures::tcp(flags,seq,ack,reverse,50000,v6);raw.timestampNs=ms*1000000;return decodeSummary(std::move(raw));
}
std::uint64_t add(TcpConversations& tracker,Packet value,std::uint64_t id=1) {value.id=id;tracker.observe(value);return value.tcpConversationId;}
void decoding() {
    for(bool v6:{false,true}) {
        auto raw=fixtures::tcp(24,42,81,true,50123,v6,{'a','b','c'});auto full=decodePacket(raw),summary=decodeSummary(raw);
        check(testing::sameSummary(full,summary),"New structured TCP fields agree across decode modes");
        check(summary.tcp && summary.tcp->sourcePort==443 && summary.tcp->destinationPort==50123 && summary.tcp->sequence==42 && summary.tcp->acknowledgment==81,"TCP metadata values");
        check(summary.tcp->payloadLength==3 && summary.tcp->completeSegment,"TCP payload length");
        raw.bytes.insert(raw.bytes.end(),20,0);check(decodeSummary(raw).tcp->payloadLength==3,"Ethernet padding excluded from TCP payload");
        raw.bytes.resize(raw.bytes.size()-21);auto cut=decodeSummary(raw);check(cut.tcp && !cut.tcp->completeSegment && !cut.error.empty(),"Payload truncation not a complete TCP segment");
        TcpConversations tracker;check(add(tracker,cut)==0 && tracker.skipped()==1,"Truncation excluded from connection inference");
    }
    auto raw=fixtures::tcp(2,100);raw.bytes[20]=0x20;auto fragment=decodeSummary(raw);
    check(fragment.tcp && !fragment.tcp->completeSegment,"Full TCP header on first IPv4 fragment not complete segment");
    TcpConversations tracker;check(!add(tracker,fragment),"First fragment excluded");
    raw.bytes.resize(42);raw.bytes[16]=0;raw.bytes[17]=28;raw.originalLength=42;
    check(!decodeSummary(raw).tcp,"Short first fragment has no structured TCP header");
    raw=fixtures::tcp(2,100);raw.bytes.insert(raw.bytes.begin()+14,{0,7,8,0});raw.bytes[12]=0x81;raw.bytes[13]=0;raw.originalLength+=4;
    check(decodeSummary(raw).vlanId==7,"Structured VLAN identity");
    auto invalid=packet(3,1);check(add(tracker,invalid)==0,"SYN FIN excluded");invalid=packet(6,1);check(add(tracker,invalid)==0,"SYN RST excluded");
}
void handshake() {
    for(bool v6:{false,true}) {
        TcpConversations tracker;const auto id=add(tracker,packet(2,100,0,false,10,v6),1);
        check(add(tracker,packet(18,500,101,true,30,v6),2)==id,"Reverse SYN ACK joins the same connection");
        add(tracker,packet(16,101,501,false,40,v6),3);const auto& item=*tracker.find(id);
        check(item.state==TcpState::Established && item.handshakeSeen && item.handshakeNs==30000000 && item.synAckNs==20000000,"Exact three way handshake and latency");
        check(item.packets[0]==2 && item.packets[1]==1 && item.eventCount==3,"Directional counts and trace events");
        check(item.events[2].packetId==3 && item.events[2].kind==TcpEventKind::Handshake,"Handshake trace packet identity");
        add(tracker,packet(18,500,101,true,50,v6),4);check(tracker.find(id)->synAckNs==20000000,"Repeated SYN ACK preserves initial latency");
    }
    TcpConversations tracker;auto id=add(tracker,packet(2,0xffffffffu,0,false,10));add(tracker,packet(18,0xffffffffu,0,true,20));add(tracker,packet(16,0,0,false,30));
    check(tracker.find(id)->state==TcpState::Established,"Handshake handles sequence wrap to zero");
    tracker.clear();id=add(tracker,packet(2,100));add(tracker,packet(18,500,100,true));add(tracker,packet(16,101,501));check(!tracker.find(id)->handshakeSeen,"Wrong SYN ACK cannot complete handshake");
    add(tracker,packet(18,500,101,true));add(tracker,packet(16,102,501));check(!tracker.find(id)->handshakeSeen,"Wrong third sequence cannot complete handshake");
    add(tracker,packet(16,101,502));check(!tracker.find(id)->handshakeSeen,"Wrong final acknowledgment cannot complete handshake");
    tracker.clear();id=add(tracker,packet(2,100,0,false,30));add(tracker,packet(18,500,101,true,20));add(tracker,packet(16,101,501,false,10));
    check(tracker.find(id)->handshakeSeen && !tracker.find(id)->handshakeNs && !tracker.find(id)->synAckNs,"Timestamp regression never yields negative latency");
    tracker.clear();id=add(tracker,packet(2,100,0,false,30));add(tracker,packet(18,500,101,true,20));add(tracker,packet(16,101,501,false,40));
    check(tracker.find(id)->handshakeSeen && !tracker.find(id)->handshakeNs,"Regressing middle timestamp also suppresses whole handshake latency");
    tracker.clear();auto tfo=decodeSummary(fixtures::tcp(2,100,0,false,50000,false,{'x','y'}));id=add(tracker,tfo);
    add(tracker,packet(18,500,103,true));add(tracker,packet(16,103,501));check(tracker.find(id)->handshakeSeen,"SYN payload consumes sequence space");
    tracker.clear();id=add(tracker,packet(16,100,500));check(tracker.find(id)->state==TcpState::Midstream,"Midstream ACK does not invent handshake");
    tracker.clear();id=add(tracker,packet(18,500,101,true));check(tracker.find(id)->state==TcpState::Midstream && !tracker.find(id)->handshakeSeen,"SYN ACK only is a partial capture");
    tracker.clear();id=add(tracker,packet(2,100));add(tracker,packet(2,500,0,true));add(tracker,packet(18,500,101,true));add(tracker,packet(16,101,501));
    check(tracker.find(id)->simultaneousOpen && !tracker.find(id)->handshakeSeen,"Simultaneous open not mislabeled ordinary handshake");
}
void closingAndReuse() {
    SessionStore store;for(auto& raw:fixtures::tcpConversationSamples())store.append(decodeSummary(std::move(raw)));
    check(store.tcp().items().size()==4,"Normal close, IPv6 reset, port reuse and midstream are separate connections");
    const auto& closed=*store.tcp().find(1);check(closed.state==TcpState::Closed && closed.synRepeats==1 && closed.handshakeNs==30000000,"FIN acknowledgments and repeated SYN recorded");
    check(closed.packets[0]==6 && closed.packets[1]==4 && closed.payloadBytes[0]==3,"Connection counters independent of packet display");
    check(store.tcp().find(2)->state==TcpState::Reset && store.tcp().find(2)->resets==1,"IPv6 reset observed");
    check(store.tcp().find(3)->state==TcpState::Handshake && store.tcp().find(4)->state==TcpState::Midstream,"Reuse and partial connection states");
    FilterSpec f;f.tcpConversationId=1;check(std::count_if(store.packets().begin(),store.packets().end(),[&](const auto& p){return f.matches(*p);})==10,"Conversation filter returns exact incarnation");
    f.ip=std::array<std::uint8_t,4>{192,0,2,1};f.ipDirection=Direction::Source;
    check(std::count_if(store.packets().begin(),store.packets().end(),[&](const auto& p){return f.matches(*p);})==6,"Conversation and address conditions intersect");
    TcpConversations tracker;auto id=add(tracker,packet(2,100));add(tracker,packet(2,100));check(tracker.items().size()==1 && tracker.find(id)->synRepeats==1,"Repeated SYN retains incarnation");
    auto next=add(tracker,packet(2,200));check(next!=id && tracker.items().size()==2,"New initial sequence starts new incarnation");
    add(tracker,packet(20,0,201,true));auto restart=add(tracker,packet(2,200));check(restart!=next,"SYN after RST starts new incarnation");
    tracker.clear();id=add(tracker,packet(17,0xffffffffu,100));check(tracker.find(id)->state==TcpState::Closing,"One FIN is not full close");
    add(tracker,packet(16,100,0,true));add(tracker,packet(17,100,0,true));check(tracker.find(id)->state==TcpState::Closing,"Two FINs without both acknowledgments still closing");
    add(tracker,packet(16,0,100));check(tracker.find(id)->state==TcpState::Closing,"ACK before FIN sequence does not acknowledge FIN");
    add(tracker,packet(16,0,101));check(tracker.find(id)->state==TcpState::Closed,"Final ACK closes both observed FINs across wrap");
}
void budgetsAndIdentity() {
    TcpConversations tracker(2);auto id=add(tracker,packet(2,100));auto next=add(tracker,packet(2,200));
    auto newest=add(tracker,packet(2,300));check(!tracker.find(id) && tracker.find(next) && tracker.find(newest) && tracker.overwritten()==1,"Reuse eviction preserves latest key mapping");
    check(add(tracker,packet(16,301,500))==newest,"Latest connection remains indexed after old incarnation evicted");
    const auto epoch=tracker.generation();tracker.clear();check(tracker.items().empty() && tracker.overwritten()==0 && tracker.generation()!=epoch,"Clear resets analysis and advances generation");
    bool rejected=false;try{TcpConversations invalid(0);}catch(const std::invalid_argument&){rejected=true;}check(rejected,"Invalid connection budget rejected");
}
void boundedLoad() {
    SessionStore store(2);for(int i=0;i<50;++i)store.append(packet(16,100,500));
    check(store.packets().size()==2 && store.tcp().find(1)->packets[0]==50,"Analysis outlives packet cache eviction without raw references");
    auto epoch=store.tcp().generation();store.clear();check(store.tcp().items().empty() && store.tcp().generation()!=epoch,"Session clearing resets TCP analysis");
    TcpConversations tracker;for(int i=0;i<60000;++i){auto p=packet(i%3?16:2,static_cast<std::uint32_t>(i));p.tcp->sourcePort=static_cast<std::uint16_t>(1024+i%60000);add(tracker,std::move(p));}
    check(tracker.items().size()==TcpConversations::connectionLimit && tracker.estimatedBytes()<2*1024*1024,"Connection count and memory stay bounded");
    tracker.clear();auto p=packet(2,100);for(int i=0;i<1000;++i)add(tracker,p,static_cast<std::uint64_t>(i+1));
    const auto& c=tracker.items().front();check(c.eventCount==16 && c.eventsOverwritten==984 && c.events[c.eventStart].packetId==985,"Trace event ring is bounded and chronological");
    auto vlan=p;vlan.vlanId=7;const auto a=add(tracker,vlan);vlan.vlanId=8;const auto b=add(tracker,vlan);check(a!=b && a!=1,"VLAN identity separates identical five tuples");
    auto reverse=packet(16,500,101,true);reverse.tcp->sourcePort=50000;reverse.tcp->destinationPort=443;const auto opposite=add(tracker,reverse);
    check(opposite!=1,"Address-port pairs, not independent address and port sorting, define endpoints");
}
}
int main() {
    try {decoding();handshake();closingAndReuse();budgetsAndIdentity();boundedLoad();std::cout<<"PASS: "<<checks<<" TCP conversation checks\n";return 0;}
    catch(const std::exception& e){std::cerr<<"FAIL after "<<checks<<" TCP checks: "<<e.what()<<'\n';return 1;}
}
