#include "core/session.h"
#include "core/tcp_stream.h"
#include "fixtures.h"
#include <algorithm>
#include <iostream>
#include <random>
#include <stdexcept>

using namespace etherscope;
namespace {
int checks{};
void check(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
Packet data(std::uint32_t sequence,std::vector<std::uint8_t> bytes,bool reverse=false,bool v6=false) {return decodeSummary(fixtures::tcp(24,sequence,1,reverse,50000,v6,std::move(bytes)));}
TcpStreamRequest request(std::vector<Packet> packets,bool syn=true) {
    SessionStore store;if(syn){store.append(decodeSummary(fixtures::tcp(2,99)));store.append(decodeSummary(fixtures::tcp(18,499,100,true)));}
    for(auto& packet:packets)store.append(std::move(packet));return *snapshotTcpStream(store,1);
}
std::vector<std::uint8_t> bytes(const StreamDirection& direction) {
    std::vector<std::uint8_t> result;for(const auto& block:direction.blocks)if(!block.bytes.empty())result.insert(result.end(),block.bytes.begin(),block.bytes.end());return result;
}
void ordinary() {
    auto r=request({data(100,{'a','b'}),data(102,{'c','d'}),data(500,{'x','y'},true)});auto result=reassembleTcp(r);
    check(bytes(result.directions[0])==std::vector<std::uint8_t>({'a','b','c','d'}) && bytes(result.directions[1])==std::vector<std::uint8_t>({'x','y'}),"Bidirectional stream data");
    check(result.directions[0].uniqueBytes==4 && result.directions[0].gaps==0 && result.directions[0].startKnown,"Known continuous direction");
    check(result.directions[0].blocks.front().packetId==3 && result.inputPackets==5,"Data provenance and snapshot count");
    auto middle=reassembleTcp(request({data(42,{'x'})},false));check(!middle.directions[0].startKnown && middle.directions[0].gaps==0,"Midstream start remains unknown");
    auto wrap=reassembleTcp(request({data(0xfffffffeu,{'a','b'}),data(0,{'c','d'})},false));check(bytes(wrap.directions[0])==std::vector<std::uint8_t>({'a','b','c','d'}) && wrap.directions[0].gaps==0,"Sequence wrap preserves contiguous data");
    auto syn=decodeSummary(fixtures::tcp(2,99,0,false,50000,false,{'a','b'}));auto tfo=request({syn,data(102,{'c'})},false);
    auto fast=reassembleTcp(tfo);check(bytes(fast.directions[0])==std::vector<std::uint8_t>({'a','b','c'}),"SYN payload begins after SYN sequence unit");
    fast=reassembleTcp(request({syn,syn},false));check(fast.events.back().kind==StreamEventKind::Duplicate && fast.events.back().sequence==100,"SYN duplicate event locates data sequence after SYN");
    for(bool v6:{false,true}) {
        SessionStore store;store.append(data(50,{'v','6'},false,v6));store.append(data(60,{'o','k'},true,v6));
        auto output=reassembleTcp(*snapshotTcpStream(store,1));check(output.directions[0].uniqueBytes==2 && output.directions[1].uniqueBytes==2,"IPv4 and IPv6 direction metadata");
    }
}
void orderAndOverlap() {
    auto result=reassembleTcp(request({data(102,{'c','d'}),data(100,{'a','b'})}));
    check(bytes(result.directions[0])==std::vector<std::uint8_t>({'a','b','c','d'}) && result.directions[0].gaps==0,"Leading hole filled by late segment");
    check(result.directions[0].gapAheadSegments==1 && result.directions[0].gapFilledSegments==1,"Gap observations attributed separately");
    result=reassembleTcp(request({data(100,{'a','b'}),data(104,{'e','f'})}));
    check(result.directions[0].gaps==1 && result.directions[0].blocks[1].bytes.empty() && result.directions[0].blocks[1].sequence==102 && result.directions[0].blocks[1].length==2,"Gap never fabricated as bytes");
    result=reassembleTcp(request({data(100,{'a','b','c'}),data(100,{'a','b','c'}),data(102,{'c','d'}),data(101,{'X','c'})}));
    check(bytes(result.directions[0])==std::vector<std::uint8_t>({'a','b','c','d'}),"First observed bytes retained through overlaps");
    check(result.directions[0].duplicateSegments==1 && result.directions[0].overlapSegments==1 && result.directions[0].conflictBytes==1,"Duplicate, overlap, and conflict distinguished");
    check(result.events.back().relatedPacketId==3 && result.events.back().packetId==6,"Conflict traces both contributing packets");
    result=reassembleTcp(request({data(100,{'a','b','c'}),data(103,{'d','e','f'}),data(100,{'a','b','c','X'})}));
    check(bytes(result.directions[0])==std::vector<std::uint8_t>({'a','b','c','d','e','f'}) && result.directions[0].conflictBytes==1 && result.events.back().relatedPacketId==4,"Conflict owner skips matching overlap pieces");
    auto noSyn=reassembleTcp(request({data(102,{'c','d'}),data(100,{'a','b'})},false));check(noSyn.directions[0].gapFilledSegments==0 && !noSyn.directions[0].startKnown,"Unknown prefix not labeled captured gap");
    auto fin=request({data(100,{'a','b'}),decodeSummary(fixtures::tcp(17,105,1))});
    result=reassembleTcp(fin);check(result.directions[0].suffixMissing && result.directions[0].gaps==1 && result.directions[0].blocks.back().length==3,"FIN exposes uncaptured suffix without zero filling");
    result=reassembleTcp(request({decodeSummary(fixtures::tcp(17,105,1))}));
    check(result.directions[0].gaps==1 && result.directions[0].prefixMissing && result.directions[0].suffixMissing && result.directions[0].blocks.front().sequence==100 && result.directions[0].blocks.front().length==5 && result.directions[0].uniqueBytes==0,"SYN and FIN bound entirely missing data");
    auto missing=request({decodeSummary(fixtures::tcp(17,105,1))});missing.end[0]=99;
    check(reassembleTcp(missing).directions[0].boundaryConflict,"Reversed empty-stream boundaries rejected");
    missing.end[0]=100+static_cast<std::uint32_t>(streamSequenceWindow)+1;
    check(reassembleTcp(missing).directions[0].limited,"Entirely missing stream obeys sequence window");
}
void bounds() {
    auto r=request({data(100,{'x'})});auto copy=std::make_shared<Packet>(*r.packets.back());copy->tcp->payloadOffset=0xffffffffu;r.packets.back()=copy;
    auto result=reassembleTcp(r);check(result.directions[0].skippedSegments==1 && result.directions[0].uniqueBytes==0,"Invalid byte range rejected");
    r=request({data(100,{'x'}),data(100+0x80000000u,{'y'})});result=reassembleTcp(r);
    check(result.directions[0].limited && result.directions[0].uniqueBytes==1,"Ambiguous half-space sequence rejected");
    r=request({data(100,{'x'}),data(100+static_cast<std::uint32_t>(streamSequenceWindow)+1,{'y'})});result=reassembleTcp(r);
    check(result.directions[0].limited && result.directions[0].uniqueBytes==1,"Sparse sequence window bounded");
    std::stop_source stop;stop.request_stop();check(reassembleTcp(r,stop.get_token()).cancelled,"Cancellation checked before packet processing");
    SessionStore small(2);small.append(decodeSummary(fixtures::tcp(2,99)));small.append(data(100,{'a'}));small.append(data(101,{'b'}));small.append(data(102,{'c'}));
    auto snapshot=*snapshotTcpStream(small,1);result=reassembleTcp(snapshot);
    check(snapshot.cachePartial && result.cachePartial && result.directions[0].prefixMissing && result.directions[0].gaps==1,"Cache eviction preserves missing prefix");
    auto previous=snapshot.packets.front();small.clear();check(reassembleTcp(snapshot).directions[0].uniqueBytes==2 && previous->raw.bytes.size()>0,"Snapshot survives session clear");
    check(!snapshotTcpStream(small,1),"Invalid conversation rejected");
    r=request({data(100,{'x'})});auto foreign=std::make_shared<Packet>(*r.packets.back());foreign->vlanId=std::uint16_t(8);r.packets.back()=foreign;
    check(reassembleTcp(r).directions[0].uniqueBytes==0,"Different VLAN never merged");
    r=request({data(100,{'a','b','c'})});r.end[0]=102;result=reassembleTcp(r);
    check(result.directions[0].boundaryConflict && !result.directions[0].suffixMissing,"Data beyond FIN is a boundary conflict");
    r.end[0].reset();r.start[0]=101;result=reassembleTcp(r);
    check(result.directions[0].boundaryConflict && !result.directions[0].prefixMissing,"Data before SYN is not a fabricated prefix gap");
    r.packets.assign(streamPacketLimit+1,{});check(reassembleTcp(r).inputLimited,"Null records also consume the input record budget");
    SessionStore large;
    for(unsigned i=0;i<300;++i)large.append(data(100+i*60000,std::vector<std::uint8_t>(60000,std::uint8_t('x'))));
    auto limited=*snapshotTcpStream(large,1);result=reassembleTcp(limited);
    check(limited.inputLimited && limited.cachePartial && result.inputLimited && result.inputRawBytes<=streamInputLimit,"Snapshot reference budget enforced");
}
void budgetsAndPermutations() {
    std::vector<Packet> packets;for(unsigned i=0;i<40;++i)packets.push_back(data(100+i*32768,std::vector<std::uint8_t>(32768,'x')));
    auto result=reassembleTcp(request(std::move(packets)));check(result.directions[0].uniqueBytes==streamDirectionLimit && result.directions[0].limited,"Per-direction data budget enforced");
    packets.clear();for(unsigned i=0;i<streamPieceLimit+10;++i)packets.push_back(data(100+2*i,{'x'}));
    result=reassembleTcp(request(std::move(packets)));check(result.directions[0].uniqueBytes==streamPieceLimit && result.directions[0].limited && result.events.size()<=streamEventLimit && result.eventsOmitted>0,"Piece and event budgets enforced");
    std::mt19937 random(1800);
    for(int i=0;i<100;++i) {
        std::vector<unsigned> order={0,1,2,3,4,5,6,7};std::shuffle(order.begin(),order.end(),random);packets.clear();
        for(auto index:order)packets.push_back(data(100+index*2,{std::uint8_t(index*2),std::uint8_t(index*2+1)}));
        result=reassembleTcp(request(std::move(packets)));const auto output=bytes(result.directions[0]);
        check(output.size()==16 && result.directions[0].gaps==0 && !result.directions[0].prefixMissing,"Permutation preserves complete coverage");
        for(std::size_t j=0;j<output.size();++j)check(output[j]==j,"Permutation byte order");
    }
}
}
int main() {try{ordinary();orderAndOverlap();bounds();budgetsAndPermutations();std::cout<<"PASS: "<<checks<<" stream checks\n";return 0;}catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<" stream checks: "<<error.what()<<'\n';return 1;}}
