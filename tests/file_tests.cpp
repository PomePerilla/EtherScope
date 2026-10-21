#include "core/capture_file.h"
#include "core/packet.h"
#include "core/session.h"
#include "fixtures.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>

using namespace etherscope;
namespace {
int checks=0;
void check(bool value,const char* what){++checks;if(!value)throw std::runtime_error(what);}
struct File {
    std::filesystem::path path=std::filesystem::temp_directory_path()/("etherscope-file-"+std::to_string(std::random_device{}())+".pcapng");
    ~File(){std::error_code error;std::filesystem::remove(path,error);}
    void write(const std::string& data){std::ofstream stream(path,std::ios::binary);stream.write(data.data(),data.size());}
};
void put(std::string& s,std::uint64_t n,unsigned width,bool little){for(unsigned i=0;i<width;++i)s.push_back(static_cast<char>(n>>((little?i:width-1-i)*8)));}
std::string block(std::uint32_t type,std::string body,bool little=true){while(body.size()%4)body+='\0';std::string s;put(s,type,4,little);put(s,body.size()+12,4,little);s+=body;put(s,body.size()+12,4,little);return s;}
std::string section(bool little=true){std::string b;put(b,0x1a2b3c4d,4,little);put(b,1,2,little);put(b,0,2,little);put(b,UINT64_MAX,8,little);return block(0x0a0d0d0a,b,little);}
std::string iface(bool little=true,std::uint8_t resolution=6,std::int64_t offset=0){std::string b;put(b,1,2,little);put(b,0,2,little);put(b,65535,4,little);put(b,9,2,little);put(b,1,2,little);b+=char(resolution);b.append(3,'\0');put(b,14,2,little);put(b,8,2,little);put(b,static_cast<std::uint64_t>(offset),8,little);return block(1,b,little);}
std::string packet(bool little,std::uint64_t ticks,std::uint32_t id=0,std::uint32_t type=6){std::string b;put(b,id,type==2?2:4,little);if(type==2)put(b,0,2,little);put(b,ticks>>32,4,little);put(b,ticks&UINT32_MAX,4,little);put(b,3,4,little);put(b,5,4,little);b+="abc";return block(type,b,little);}
bool rejects(const std::string& data){File f;f.write(data);try{CaptureReader r(f.path);while(r.next()){}return false;}catch(const std::exception&){return true;}}
void readerCases(){
    File f;
    for(bool little:{true,false}){
        f.write(section(little)+iface(little)+packet(little,1234567));CaptureReader r(f.path);auto p=r.next();check(p && p->timestampNs==1234567000 && p->bytes==std::vector<std::uint8_t>({'a','b','c'}),"Endian EPB");check(!r.next(),"EOF");
        f.write(section(little)+iface(little,0x8a,2)+packet(little,1536,0,2));CaptureReader binary(f.path);check(binary.next()->timestampNs==3500000000,"Binary timestamp and old packet block");
    }
    f.write(section()+iface()+packet(true,1)+section(false)+iface(false,9)+packet(false,5));CaptureReader multiple(f.path);auto a=multiple.next(),b=multiple.next();check(a->interfaceId!=b->interfaceId && b->timestampNs==5,"Section-local interface identity");
    f.write(section()+iface()+block(0x12345678,"unknown")+packet(true,7));CaptureReader unknown(f.path);check(unknown.next()->timestampNs==7000,"Unknown block skipped");
    std::string spb;put(spb,3,4,true);spb+="abc";f.write(section()+iface()+block(3,spb));CaptureReader simple(f.path);check(!simple.next()->timestampValid,"SPB missing timestamp");
    check(rejects(section()+iface()+packet(true,1,2)),"Invalid interface rejected");
    auto valid=section()+iface()+packet(true,1);for(std::size_t n=1;n<valid.size();++n)if(n!=28 && n!=iface().size()+28)check(rejects(valid.substr(0,n)),"Truncated blocks rejected");
    valid.back()^=1;check(rejects(valid),"Trailing length checked");
    check(rejects(section()+iface(true,0xff)),"Resolution bound");
    f.write(section()+iface(true,19)+packet(true,UINT64_MAX));CaptureReader fine(f.path);check(fine.next()->timestampNs==1844674407,"Fine decimal timestamp no overflow");
}
void writerCases(){
    Packet a=decodeSummary(fixtures::icmp(8));
    a.raw.timestampNs=1234567891;a.raw.interfaceId=5;auto info=std::make_shared<CaptureInterfaceInfo>();info->name="eth0";a.raw.interfaceInfo=info;
    Packet b=a;b.raw.interfaceId=9;b.raw.linkType=101;b.raw.bytes={1,2,3};b.raw.originalLength=3;
    std::vector<const Packet*> list{&a,&b};std::ostringstream stream(std::ios::binary);writeCapture(stream,list,CaptureFormat::Pcapng);File f;f.write(stream.str());CaptureReader r(f.path);
    auto x=r.next(),y=r.next();check(x->bytes==a.raw.bytes && x->timestampNs==a.raw.timestampNs && x->interfaceInfo->name=="eth0","PCAPNG roundtrip");check(y->linkType==101 && x->interfaceId!=y->interfaceId,"Mixed links preserved");check(decodeSummary(*y).error.empty(),"Opaque link is not malformed");
    bool failed=false;try{std::ostringstream legacy;writeCapture(legacy,list,CaptureFormat::Pcap);}catch(...){failed=true;}check(failed,"Classic mixed interfaces rejected");
    a.raw.timestampValid=false;list={&a};std::ostringstream simple;writeCapture(simple,list,CaptureFormat::Pcapng);f.write(simple.str());CaptureReader spb(f.path);check(!spb.next()->timestampValid,"SPB export");
}
}
int main(){try{readerCases();writerCases();std::cout<<checks<<" file checks passed\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
