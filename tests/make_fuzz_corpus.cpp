#include "fixtures.h"
#include <filesystem>
#include <fstream>

int main(int argc,char** argv) {
    if(argc!=2)return 2;
    const std::filesystem::path directory(argv[1]);std::filesystem::create_directories(directory);
    auto raws=etherscope::fixtures::samples();
    for(auto list:{etherscope::fixtures::ipv6Samples(),etherscope::fixtures::analysisSamples()})raws.insert(raws.end(),list.begin(),list.end());
    std::vector<std::uint8_t> dense(24,0);dense[0]=135;
    for(int i=0;i<3000;++i)dense.insert(dense.end(),{1,1,0,1,2,3,4,5});
    raws.push_back(etherscope::fixtures::ipv6(58,dense,255));
    std::size_t number=0;
    for(const auto& raw:raws)for(int kind=0;kind<3;++kind) {
        auto bytes=raw.bytes;if(kind==1)bytes.resize(bytes.size()/2);if(kind==2 && !bytes.empty())bytes.back()^=255;
        std::ofstream file(directory/std::to_string(number++),std::ios::binary);
        file.put(1);for(unsigned shift=0;shift<32;shift+=8)file.put(static_cast<char>(raw.originalLength>>shift));
        file.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
        if(!file)return 1;
    }
}
