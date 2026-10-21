#include "core/application_analyzer.h"
#include "core/capture_file.h"
#include "core/session.h"
#include <fstream>
#include <iostream>

using namespace etherscope;
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
#else
int main(int argc,char** argv) {
#endif
    if(argc<2)return 2;
    try {
        TlsKeyLog keys;if(argc>2){std::ifstream file{std::filesystem::path(argv[2])};const std::string data{std::istreambuf_iterator<char>(file),{}};keys.append(data);}
        CaptureReader reader{std::filesystem::path(argv[1])};SessionStore store;
#ifdef _WIN32
        const bool plaintext=argc>3 && std::wstring_view(argv[3])==L"--plaintext";
#else
        const bool plaintext=argc>3 && std::string_view(argv[3])=="--plaintext";
#endif
        while(auto packet=reader.next())store.append(decodeSummary(std::move(*packet)));
        auto print=[&](const ApplicationResult& result){
            std::cout<<"status\t"<<int(result.status)<<'\t'<<result.error<<'\n';
            for(const auto& m:result.messages)for(const auto& f:m.fields)if(!f.key.empty())std::cout<<m.protocol<<'\t'<<f.key<<'\t'<<applicationText(f.value)<<'\n';
            if(plaintext)for(const auto& m:result.messages)if(m.protocol=="TLS" && m.source==DataSource::Decrypted && m.summary=="Application data"){
                std::cout<<"plaintext\t"<<m.direction<<'\t';for(std::size_t i=m.offset;i<m.offset+m.length;++i){const auto byte=(*m.bytes)[i];std::cout<<"0123456789abcdef"[byte>>4]<<"0123456789abcdef"[byte&15];}std::cout<<'\n';
            }
        };
        for(const auto& p:store.packets())if(p->udp)print(analyzeDatagram(*p));
        for(const auto& c:store.tcp().items())if(auto request=snapshotTcpStream(store,c.id))print(analyzeConversation(*request,keys));
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
