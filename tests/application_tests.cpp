#include "core/application.h"
#include "core/display_filter.h"
#include "core/tls.h"
#include "fixtures.h"
#include <openssl/evp.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace etherscope;
namespace {
int checks=0;
void check(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
using Bytes=std::vector<std::uint8_t>;
Bytes hex(std::string_view text){Bytes out;auto digit=[](char c){return c<='9'?c-'0':c-'a'+10;};for(std::size_t i=0;i<text.size();i+=2)out.push_back(static_cast<std::uint8_t>((digit(text[i])<<4)|digit(text[i+1])));return out;}
std::string hexText(std::span<const std::uint8_t> bytes){std::string out;for(auto b:bytes){out+="0123456789abcdef"[b>>4];out+="0123456789abcdef"[b&15];}return out;}
void put(Bytes& out,std::uint64_t n,unsigned width){for(unsigned i=0;i<width;++i)out.push_back(static_cast<std::uint8_t>(n>>((width-1-i)*8)));}
void append(Bytes& a,std::span<const std::uint8_t> b){a.insert(a.end(),b.begin(),b.end());}
ApplicationInput input(Bytes bytes,unsigned side=0,std::uint64_t id=1){ApplicationInput in;in.bytes=std::make_shared<const Bytes>(std::move(bytes));in.sources={{id,54,in.bytes->size(),0}};in.direction=side;in.startKnown=true;in.endKnown=true;return in;}
ApplicationInput input(std::string_view text,unsigned side=0,std::uint64_t id=1){return input(Bytes(text.begin(),text.end()),side,id);}
bool has(const ApplicationResult& r,const std::string& key,const ApplicationValue& value){for(const auto& m:r.messages)for(const auto& f:m.fields)if(f.key==key && f.value==value)return true;return false;}
void dns(){
    auto query=hex("123401000001000000000000076578616d706c6503636f6d0000010001");auto r=decodeDns(input(query));check(r.status==AnalysisStatus::Complete && has(r,"dns.qry.name",std::string("example.com")),"DNS question");
    query[2]=0x81;query[3]=0x80;query[7]=1;append(query,hex("c00c000100010000003c0004c0000201"));r=decodeDns(input(query));check(has(r,"dns.a",std::string("192.0.2.1")),"DNS compressed answer");
    auto loop=hex("000001000001000000000000c00c00010001");check(decodeDns(input(loop)).status==AnalysisStatus::Incomplete,"DNS pointer loop rejected");
    for(std::size_t n=0;n<query.size();++n){auto shortInput=input(Bytes(query.begin(),query.begin()+static_cast<std::ptrdiff_t>(n)));check(decodeDns(shortInput).status!=AnalysisStatus::Complete,"DNS truncation");}
}
void http(){
    auto r=decodeHttp1({input("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHEAD /x HTTP/1.1\r\n\r\n"),input("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",1,2)});
    check(r.status==AnalysisStatus::Complete && r.messages.size()==4 && has(r,"http.host",std::string("example.com")),"HTTP pipelining and HEAD");
    r=decodeHttp1({input("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-Test: yes\r\n\r\n"),{}});check(r.status==AnalysisStatus::Complete && r.messages.size()==1,"Chunked HTTP and trailers");
    r=decodeHttp1({input("GET / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),{}});check(r.status==AnalysisStatus::Incomplete,"Conflicting HTTP framing");
    r=decodeHttp1({input("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nx"),{}});check(r.status==AnalysisStatus::Incomplete && has(r,"http.host",std::string("example.com")),"Incomplete HTTP body retains headers");
    std::string repeated;for(unsigned n=0;n<1024;++n)repeated+="GET / HTTP/1.1\r\nHost: example.com\r\nX-A: a\r\nX-B: b\r\n\r\n";
    r=decodeHttp1({input(repeated),{}});std::size_t nodes=0;for(const auto& message:r.messages)nodes+=message.fields.size();check(r.status==AnalysisStatus::Limited && nodes<=maxPacketFields,"Application node budget spans messages");
}
Bytes frame(unsigned type,unsigned flags,unsigned stream,const Bytes& data){Bytes b;put(b,data.size(),3);put(b,type,1);put(b,flags,1);put(b,stream,4);append(b,data);return b;}
void http2(){
    const std::string preface="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";Bytes a(preface.begin(),preface.end());append(a,frame(4,0,0,{}));auto headers=hex("828684410f7777772e6578616d706c652e636f6d");append(a,frame(1,5,1,headers));
    Bytes b=frame(4,0,0,{});append(b,frame(1,5,1,hex("88")));auto r=decodeHttp2({input(a),input(b,1,2)});check(r.status==AnalysisStatus::Complete && has(r,"http.host",std::string("www.example.com")) && has(r,"http.response.code",std::uint64_t(200)),"HTTP/2 HPACK RFC example");
    a.assign(preface.begin(),preface.end());append(a,frame(4,0,0,{}));append(a,frame(1,1,1,Bytes(headers.begin(),headers.begin()+4)));append(a,frame(9,4,1,Bytes(headers.begin()+4,headers.end())));r=decodeHttp2({input(a),input(b,1,2)});check(r.status==AnalysisStatus::Complete && has(r,"http.host",std::string("www.example.com")),"HTTP/2 CONTINUATION");
    a.assign(preface.begin(),preface.end());append(a,frame(4,0,0,{}));append(a,frame(1,5,1,hex("be")));check(decodeHttp2({input(a),input(b,1,2)}).status==AnalysisStatus::Incomplete,"Missing HPACK dynamic state");
}
void filters(){
    auto p=decodeSummary(fixtures::tcp(2,100));p.id=42;
    for(const auto expression:{"tcp && tcp.flags.syn","frame.number == 42 and not udp","tcp.port in {443,50000}","ip.addr in {192.0.2.0/24,198.51.100.0/24}","tcp.port != 443"}){auto f=compileDisplayFilter(expression);check(bool(f.value),"Expression compiled");check(f.value->evaluate(p)==FilterTruth::True,"Basic expression match");}
    p.tcp->payloadLength=1;auto f=compileDisplayFilter("not http.host contains \"example\"");check(f.value && f.value->evaluate(p)==FilterTruth::Unknown,"NOT preserves pending analysis");ApplicationFacts facts;facts.status=AnalysisStatus::Complete;check(f.value->evaluate(p,&facts)==FilterTruth::True,"Complete absent field");facts.values["http.host"]={std::string("example.com")};check(f.value->evaluate(p,&facts)==FilterTruth::False,"Application predicate");
    f=compileDisplayFilter("false_field == 1");check(!f.value && f.position==0,"Unknown field rejected");
    for(const auto expression:{"tcp.port == -1","tcp.port == \"hello\"","ip.addr == ::1","ip.addr == 192.0.2.1/33","tcp contains x","tcp.port in {}","tcp &&","(tcp","http.host == \"unterminated"})check(!compileDisplayFilter(expression).value,"Invalid filter rejected");
    check(!compileDisplayFilter(std::string(4097,'x')).value,"Expression length bound");
}
void crypto(){
    const Bytes key(16),iv(12);auto plain=tls::decrypt(*tls::cipher(0x1301,true),key,iv,{},hex("0388dace60b6a392f328c2b971b2fe78"),hex("ab6e47d42cec13bdf53a67b21257bddf"));check(plain && *plain==Bytes(16),"NIST AES-GCM vector");
    auto bad=hex("ab6e47d42cec13bdf53a67b21257bdde");check(!tls::decrypt(*tls::cipher(0x1301,true),key,iv,{},hex("0388dace60b6a392f328c2b971b2fe78"),bad),"AEAD authentication rejection");
    Bytes secret(32);for(std::size_t i=0;i<secret.size();++i)secret[i]=static_cast<std::uint8_t>(i);check(hexText(tls::expandLabel(secret,"SHA256","key",16))=="9c9783cf77ea32d44f369da41f19f3cc","TLS 1.3 fixed KDF vector");
    secret.resize(48);for(std::size_t i=0;i<secret.size();++i)secret[i]=static_cast<std::uint8_t>(i);const std::string label="key expansion";Bytes seed(label.begin(),label.end());for(unsigned i=0;i<64;++i)seed.push_back(static_cast<std::uint8_t>(i));check(hexText(tls::prf(secret,"SHA256",seed,40))=="4ac38c4d46e5ff44538c63cd6644009fd1aa1b19a81b76452615cb3f94ce61ea9f2477bd23b09dfa","TLS 1.2 fixed PRF vector");
    TlsKeyLog keys;const auto line="CLIENT_RANDOM "+std::string(64,'0')+" "+std::string(96,'0')+"\n";check(keys.append(line) && !keys.append(line) && keys.revision()==1,"Key log merge");const auto revision=keys.revision();bool failed=false;try{keys.append(line+"bad\n");}catch(...){failed=true;}check(failed && keys.revision()==revision,"Invalid key log preserves existing keys");
}
}
int main(){try{dns();http();http2();filters();crypto();std::cout<<checks<<" application checks passed\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
