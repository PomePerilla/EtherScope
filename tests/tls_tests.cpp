#include "core/tls.h"
#include "core/application_stream.h"
#include <openssl/evp.h>
#include <iostream>
#include <stdexcept>
#include <sstream>

using namespace etherscope;
namespace {
using Bytes=std::vector<std::uint8_t>;
int checks=0;
void check(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
void put(Bytes& out,std::uint64_t n,unsigned width){for(unsigned i=0;i<width;++i)out.push_back(static_cast<std::uint8_t>(n>>((width-1-i)*8)));}
void append(Bytes& out,std::span<const std::uint8_t> bytes){out.insert(out.end(),bytes.begin(),bytes.end());}
std::string hex(const Bytes& bytes){std::string out;for(auto b:bytes){out+="0123456789abcdef"[b>>4];out+="0123456789abcdef"[b&15];}return out;}
Bytes handshake(unsigned type,Bytes bytes){Bytes out;put(out,type,1);put(out,bytes.size(),3);append(out,bytes);return out;}
Bytes record(unsigned type,const Bytes& bytes){Bytes out;put(out,type,1);put(out,0x0303,2);put(out,bytes.size(),2);append(out,bytes);return out;}
Bytes hello(bool server,std::uint16_t suite,bool v13,const Bytes& random){
    Bytes out;put(out,0x0303,2);append(out,random);out.push_back(0);
    if(server){put(out,suite,2);out.push_back(0);}else{put(out,2,2);put(out,suite,2);out.push_back(1);out.push_back(0);}
    Bytes extensions;
    if(v13){put(extensions,43,2);put(extensions,server?2:3,2);if(!server)extensions.push_back(2);put(extensions,0x0304,2);}
    if(!server){const std::string host="example.com";put(extensions,0,2);put(extensions,host.size()+5,2);put(extensions,host.size()+3,2);extensions.push_back(0);put(extensions,host.size(),2);extensions.insert(extensions.end(),host.begin(),host.end());}
    if(server && !v13){const std::string alpn="http/1.1";put(extensions,16,2);put(extensions,alpn.size()+3,2);put(extensions,alpn.size()+1,2);extensions.push_back(static_cast<std::uint8_t>(alpn.size()));extensions.insert(extensions.end(),alpn.begin(),alpn.end());}
    put(out,extensions.size(),2);append(out,extensions);return record(22,handshake(server?2:1,out));
}
Bytes seal(const tls::Cipher& cipher,const Bytes& key,Bytes iv,const Bytes& plaintext,unsigned type,std::uint64_t sequence){
    Bytes body=plaintext,aad,explicitNonce;
    if(cipher.tls13){body.push_back(static_cast<std::uint8_t>(type));for(unsigned i=0;i<8;++i)iv[iv.size()-1-i]^=static_cast<std::uint8_t>(sequence>>(i*8));aad={23,3,3};put(aad,body.size()+16,2);}
    else {
        if(cipher.chacha){for(unsigned i=0;i<8;++i)iv[iv.size()-1-i]^=static_cast<std::uint8_t>(sequence>>(i*8));}
        else {put(explicitNonce,sequence,8);append(iv,explicitNonce);}
        put(aad,sequence,8);put(aad,type,1);put(aad,0x0303,2);put(aad,body.size(),2);
    }
    auto algorithm=std::unique_ptr<EVP_CIPHER,decltype(&EVP_CIPHER_free)>(EVP_CIPHER_fetch(nullptr,cipher.name,nullptr),EVP_CIPHER_free);
    auto context=std::unique_ptr<EVP_CIPHER_CTX,decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);Bytes encrypted(body.size()+16),tag(16);int n=0,total=0;
    check(algorithm && context,"Test cipher context");
    check(EVP_EncryptInit_ex(context.get(),algorithm.get(),nullptr,nullptr,nullptr)==1 && EVP_CIPHER_CTX_ctrl(context.get(),EVP_CTRL_AEAD_SET_IVLEN,12,nullptr)==1 && EVP_EncryptInit_ex(context.get(),nullptr,nullptr,key.data(),iv.data())==1,"Test cipher initialization");
    check(EVP_EncryptUpdate(context.get(),nullptr,&n,aad.data(),static_cast<int>(aad.size()))==1 && EVP_EncryptUpdate(context.get(),encrypted.data(),&n,body.data(),static_cast<int>(body.size()))==1,"Test cipher data");total=n;check(EVP_EncryptFinal_ex(context.get(),encrypted.data()+total,&n)==1,"Test cipher final");encrypted.resize(static_cast<std::size_t>(total+n));check(EVP_CIPHER_CTX_ctrl(context.get(),EVP_CTRL_AEAD_GET_TAG,16,tag.data())==1,"Test cipher tag");append(explicitNonce,encrypted);append(explicitNonce,tag);return record(cipher.tls13?23:type,explicitNonce);
}
struct Case {
    std::array<ApplicationInput,2> input;
    std::string keylog;
    std::array<Bytes,2> bytes;
    void add(unsigned side,std::uint64_t packet,Bytes record){input[side].sources.push_back({packet,54,record.size(),bytes[side].size()});append(bytes[side],record);}
    void finish(){for(unsigned side=0;side<2;++side){input[side].bytes=std::make_shared<const Bytes>(bytes[side]);input[side].direction=side;input[side].startKnown=input[side].endKnown=true;}}
};
Case sample(std::uint16_t suite,bool v13,bool update=false){
    Case c;const auto cipher=*tls::cipher(suite,v13);Bytes random(32,0x11),server(32,0x22);c.add(0,1,hello(false,suite,v13,random));c.add(1,2,hello(true,suite,v13,server));
    std::array<Bytes,2> keys,ivs,appSecrets;const auto hashSize=std::string_view(cipher.hash)=="SHA384"?48u:32u;
    if(v13){
        for(unsigned side=0;side<2;++side){Bytes hs(hashSize,static_cast<std::uint8_t>(side+1));appSecrets[side]=Bytes(hashSize,static_cast<std::uint8_t>(side+3));const std::string prefix=side?"SERVER_":"CLIENT_";c.keylog+=prefix+"HANDSHAKE_TRAFFIC_SECRET "+hex(random)+" "+hex(hs)+"\n"+prefix+"TRAFFIC_SECRET_0 "+hex(random)+" "+hex(appSecrets[side])+"\n";keys[side]=tls::expandLabel(hs,cipher.hash,"key",cipher.keyLength);ivs[side]=tls::expandLabel(hs,cipher.hash,"iv",12);}
    }else{
        Bytes master(48,0x33);c.keylog="CLIENT_RANDOM "+hex(random)+" "+hex(master)+"\n";const std::string label="key expansion";Bytes seed(label.begin(),label.end());append(seed,server);append(seed,random);const auto material=tls::prf(master,cipher.hash,seed,2*(cipher.keyLength+cipher.ivLength));
        for(unsigned side=0;side<2;++side){keys[side].assign(material.begin()+static_cast<std::ptrdiff_t>(side*cipher.keyLength),material.begin()+static_cast<std::ptrdiff_t>((side+1)*cipher.keyLength));ivs[side].assign(material.begin()+static_cast<std::ptrdiff_t>(2*cipher.keyLength+side*cipher.ivLength),material.begin()+static_cast<std::ptrdiff_t>(2*cipher.keyLength+(side+1)*cipher.ivLength));}
        c.add(1,3,record(20,{1}));c.add(0,4,record(20,{1}));
    }
    c.add(1,5,seal(cipher,keys[1],ivs[1],handshake(20,Bytes(v13?hashSize:12,0)),22,0));c.add(0,6,seal(cipher,keys[0],ivs[0],handshake(20,Bytes(v13?hashSize:12,0)),22,0));
    if(v13)for(unsigned side=0;side<2;++side){keys[side]=tls::expandLabel(appSecrets[side],cipher.hash,"key",cipher.keyLength);ivs[side]=tls::expandLabel(appSecrets[side],cipher.hash,"iv",12);}
    const std::string request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",response="HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    c.add(0,7,seal(cipher,keys[0],ivs[0],Bytes(request.begin(),request.end()),23,v13?0:1));c.add(1,8,seal(cipher,keys[1],ivs[1],Bytes(response.begin(),response.end()),23,v13?0:1));
    if(update){c.add(0,9,seal(cipher,keys[0],ivs[0],handshake(24,{0}),22,1));appSecrets[0]=tls::expandLabel(appSecrets[0],cipher.hash,"traffic upd",hashSize);keys[0]=tls::expandLabel(appSecrets[0],cipher.hash,"key",cipher.keyLength);ivs[0]=tls::expandLabel(appSecrets[0],cipher.hash,"iv",12);c.add(0,10,seal(cipher,keys[0],ivs[0],Bytes(request.begin(),request.end()),23,0));}
    c.finish();return c;
}
void run(){
    for(bool v13:{false,true}) {
        const auto suites=v13?std::vector<std::uint16_t>{0x1301,0x1302,0x1303}:std::vector<std::uint16_t>{0x009c,0x009d,0x009e,0x009f,0xc02b,0xc02c,0xc02f,0xc030,0xcca8,0xcca9,0xccaa};
        for(auto suite:suites){auto c=sample(suite,v13,v13);TlsKeyLog keys;keys.append(c.keylog);auto result=decodeTls(c.input,keys);if(result.analysis.status!=AnalysisStatus::Complete)throw std::runtime_error(std::to_string(suite)+": "+result.analysis.error);check(result.decrypted,"TLS decryption");const auto http=decodeHttp1(result.plaintext);check(http.status==AnalysisStatus::Complete && http.messages.size()==(v13?3u:2u),"TLS plaintext HTTP parsing");for(const auto& message:http.messages)check(!message.sources.empty() && message.source==DataSource::Decrypted,"Plaintext source mapping");
            TlsStream stream;
            std::map<std::uint64_t, std::pair<unsigned, SourceSpan>> records;
            for (unsigned side = 0; side < 2; ++side)
                for (const auto &source : c.input[side].sources)
                    records[source.packetId] = {side, source};
            std::array<Bytes, 2> plaintext;
            TlsResult incremental;
            for (const auto &[packet, item] : records) {
                const auto &[side, source] = item;
                for (std::size_t offset = 0; offset < source.length; ++offset) {
                    std::array<ApplicationInput, 2> input;
                    auto &part = input[side];
                    part.direction = side;
                    part.startKnown = true;
                    part.bytes = std::make_shared<const Bytes>(1, c.bytes[side][source.bufferOffset + offset]);
                    part.sources = {{packet, 54 + offset, 1, 0}};
                    incremental = stream.append(input, keys);
                    for (unsigned direction = 0; direction < 2; ++direction)
                        if (incremental.plaintext[direction].bytes)
                            append(plaintext[direction], *incremental.plaintext[direction].bytes);
                }
            }
            if (incremental.analysis.status != AnalysisStatus::Complete)
                throw std::runtime_error("Incremental suite " + std::to_string(suite) + ": " + incremental.analysis.error);
            check(plaintext[0] == *result.plaintext[0].bytes && plaintext[1] == *result.plaintext[1].bytes,
                  "Incremental TLS one-byte records and KeyUpdate equal whole-input plaintext");
            check(incremental.analysis.messages.size() == result.analysis.messages.size(),
                  "Incremental TLS never duplicates handshake or application messages");
            for (const auto &message : incremental.analysis.messages) {
                check(message.bytes && message.streamOffset.has_value(), "Incremental TLS messages own stable ranges");
                for (const auto &source : message.sources) {
                    const auto record = records.at(source.packetId).second;
                    check(source.rawOffset >= record.rawOffset && source.rawOffset + source.length <= 54 + record.length,
                          "TLS source ranges stay inside their carrier packet");
                    const auto logical = source.bufferLength ? source.bufferLength : source.length;
                    check(source.bufferOffset <= message.bytes->size() && logical <= message.bytes->size() - source.bufferOffset,
                          "TLS source ranges stay inside their published data source");
                }
                for (const auto &field : message.fields)
                    check(field.offset <= message.bytes->size() && field.length <= message.bytes->size() - field.offset,
                          "Incremental TLS field ranges stay inside immutable data");
            }
        }
    }
    for(bool v13:{false,true}){
        auto reordered=sample(v13?0x1301:0xc02b,v13,v13);TlsKeyLog log;log.append(reordered.keylog);
        for(auto& direction:reordered.input)for(auto& source:direction.sources)source.packetId=100-source.packetId;
        auto decoded=decodeTls(reordered.input,log);check(decoded.analysis.status==AnalysisStatus::Complete && decoded.decrypted,"TLS reordered records preserve directional sequence");
        check(decodeHttp1(decoded.plaintext).messages.size()==(v13?3u:2u),"Reordered TLS application data");
    }
    auto c=sample(0x1301,true);TlsKeyLog empty;auto missing=decodeTls(c.input,empty);check(missing.analysis.status==AnalysisStatus::MissingKeys && !missing.decrypted,"Missing key status");
    {
        TlsKeyLog full;
        full.append(c.keylog);
        TlsStream deferred;
        auto result = deferred.append(c.input, empty);
        check(result.analysis.status == AnalysisStatus::MissingKeys, "Incremental TLS pauses without keys");
        result = deferred.append({}, full);
        check(result.analysis.status == AnalysisStatus::Complete && result.decrypted,
              "Incremental TLS resumes buffered records when keys arrive");
        TlsKeyLog handshakeOnly;
        std::string partial;
        std::istringstream lines(c.keylog);
        std::string line;
        while (std::getline(lines, line))
            if (line.find("HANDSHAKE_TRAFFIC_SECRET") != std::string::npos)
                partial += line + '\n';
        handshakeOnly.append(partial);
        TlsStream phase;
        auto pending = phase.append(c.input, handshakeOnly);
        check(pending.analysis.status == AnalysisStatus::MissingKeys,
              "Missing application secret never reuses the handshake key");
        pending = phase.append({}, full);
        check(pending.analysis.status == AnalysisStatus::Complete &&
                  *pending.plaintext[0].bytes == *result.plaintext[0].bytes &&
                  *pending.plaintext[1].bytes == *result.plaintext[1].bytes,
              "Incremental TLS resumes at the correct direction and key epoch");
    }
    TlsKeyLog keys;keys.append(c.keylog);c.bytes[0].back()^=1;c.input[0].bytes=std::make_shared<const Bytes>(c.bytes[0]);auto invalid=decodeTls(c.input,keys);check(invalid.analysis.status==AnalysisStatus::AuthenticationFailed && invalid.plaintext[0].bytes->empty(),"Tampered plaintext never published");
}
}
int main(){try{run();std::cout<<checks<<" TLS checks passed\n";return 0;}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
