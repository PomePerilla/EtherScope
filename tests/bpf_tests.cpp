#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <pcap/pcap.h>
#include "fixtures.h"
#include <algorithm>
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>

namespace {
struct Library {
    HMODULE module{};
    Library() {
        wchar_t system[MAX_PATH]{};if(!GetSystemDirectoryW(system,MAX_PATH))throw std::runtime_error("System directory missing");
        const auto path=std::filesystem::path(system)/L"Npcap"/L"wpcap.dll";
        module=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!module)throw std::runtime_error("Npcap unavailable");
    }
    ~Library(){if(module)FreeLibrary(module);}
    template<class T>T symbol(const char* name){auto value=reinterpret_cast<T>(GetProcAddress(module,name));if(!value)throw std::runtime_error(name);return value;}
};
}
int main() {
    try {
        Library library;
        const auto open=library.symbol<decltype(&pcap_open_dead)>("pcap_open_dead");
        const auto close=library.symbol<decltype(&pcap_close)>("pcap_close");
        const auto compile=library.symbol<decltype(&pcap_compile)>("pcap_compile");
        const auto free=library.symbol<decltype(&pcap_freecode)>("pcap_freecode");
        const auto matches=library.symbol<decltype(&pcap_offline_filter)>("pcap_offline_filter");
        auto* handle=open(DLT_EN10MB,65535);if(!handle)throw std::runtime_error("Offline handle missing");
        struct Guard {pcap_t* p;decltype(&pcap_close) close;~Guard(){close(p);}} guard{handle,close};
        auto raws=etherscope::fixtures::samples();auto ipv6=etherscope::fixtures::ipv6Samples();raws.insert(raws.end(),ipv6.begin(),ipv6.end());
        auto type=[](const etherscope::RawPacket& r){return (r.bytes[12]<<8)|r.bytes[13];};
        using Test=std::pair<const char*,std::function<bool(const etherscope::RawPacket&)>>;
        const Test tests[]={
            {"",[](const auto&){return true;}},{"ip",[&](const auto& r){return type(r)==0x800;}},
            {"ip6",[&](const auto& r){return type(r)==0x86dd;}},{"arp",[&](const auto& r){return type(r)==0x806;}},
            {"icmp",[&](const auto& r){return type(r)==0x800 && r.bytes[23]==1;}},
            {"icmp6",[&](const auto& r){return type(r)==0x86dd && r.bytes[20]==58;}},
            {"ether src 02:00:00:00:00:01",[](const auto& r){const std::uint8_t expected[]={2,0,0,0,0,1};return std::equal(expected,expected+6,r.bytes.begin()+6);}},
            {"tcp port 443",[&](const auto& r){return r.bytes==raws[5].bytes || r.bytes==raws[14].bytes;}},
            {"vlan and icmp",[&](const auto& r){return r.bytes==raws[8].bytes;}},
            {"ip and src host 192.0.2.1",[&](const auto& r){return type(r)==0x800 && r.bytes[26]==192 && r.bytes[27]==0 && r.bytes[28]==2 && r.bytes[29]==1;}}
        };
        unsigned checks=0;
        for(const auto& [expression,expected]:tests) {
            bpf_program program{};if(compile(handle,&program,expression,1,PCAP_NETMASK_UNKNOWN)!=0)throw std::runtime_error(expression);
            struct Code {bpf_program* p;decltype(&pcap_freecode) free;~Code(){free(p);}} code{&program,free};
            for(const auto& raw:raws) {
                pcap_pkthdr header{};header.caplen=static_cast<bpf_u_int32>(raw.bytes.size());header.len=raw.originalLength;
                if((matches(&program,&header,raw.bytes.data())!=0)!=expected(raw))throw std::runtime_error(std::string(expression)+" packet="+std::to_string(&raw-raws.data())+" matched="+std::to_string(matches(&program,&header,raw.bytes.data())!=0));
                ++checks;
            }
        }
        bpf_program invalid{};if(compile(handle,&invalid,"bad (",1,PCAP_NETMASK_UNKNOWN)==0){free(&invalid);throw std::runtime_error("Invalid filter accepted");}
        std::cout<<"{\"kind\":\"npcap_offline_fixed_packet_filtering\",\"packets\":"<<raws.size()<<",\"checks\":"<<checks+1<<",\"passed\":true}\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
