#include "fixtures.h"
#include "core/session.h"
#include "core/pcap_file.h"
#include <chrono>
#include <iostream>
#include <streambuf>
#include <string_view>

namespace {
class CountingBuffer final:public std::streambuf {
public:
    std::uint64_t bytes{};
protected:
    std::streamsize xsputn(const char*,std::streamsize count) override {
        bytes+=static_cast<std::uint64_t>(count);return count;
    }
    int_type overflow(int_type value) override {
        if(!traits_type::eq_int_type(value,traits_type::eof()))++bytes;
        return traits_type::not_eof(value);
    }
};
}
int main(int argc,char** argv) {
    const int count=argc>1?std::stoi(argv[1]):100000;
    if(count<1)return 1;
    const bool summary=argc>2 && std::string_view(argv[2])=="summary";
    auto raws=etherscope::fixtures::samples();
    const auto ipv6=etherscope::fixtures::ipv6Samples();raws.insert(raws.end(),ipv6.begin(),ipv6.end());
    etherscope::SessionStore store;
    const auto start=std::chrono::steady_clock::now();
    for(int i=0;i<count;++i)store.append(summary?etherscope::decodeSummary(raws[static_cast<std::size_t>(i)%raws.size()]):etherscope::decodePacket(raws[static_cast<std::size_t>(i)%raws.size()]));
    const double seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
    std::vector<const etherscope::Packet*> packets;
    for(const auto& packet:store.packets())packets.push_back(packet.get());
    CountingBuffer buffer;std::ostream output(&buffer);
    const auto writeStart=std::chrono::steady_clock::now();
    const int repetitions=100;
    for(int i=0;i<repetitions;++i)etherscope::writePcap(output,packets);
    const double writeSeconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-writeStart).count();
    std::cout<<"{\"kind\":\"synthetic_mixed_core_and_pcap_encoding\",\"packets\":"<<count
        <<",\"decode_mode\":\""<<(summary?"summary":"full")<<"\",\"retained_estimated_bytes\":"<<store.estimatedBytes()
        <<",\"seconds\":"<<seconds<<",\"packets_per_second\":"<<count/seconds
        <<",\"retained\":"<<store.packets().size()<<",\"raw_bytes\":"<<store.rawBytes()
        <<",\"overwritten\":"<<store.stats().overwritten<<",\"pcap_records\":"<<packets.size()*repetitions
        <<",\"pcap_encoding_seconds\":"<<writeSeconds<<",\"pcap_records_per_second\":"<<packets.size()*repetitions/writeSeconds
        <<",\"encoded_bytes\":"<<buffer.bytes<<"}\n";
    return store.packets().size()<=10000 && store.rawBytes()<=64*1024*1024?0:1;
}
