#include "core/capture_file.h"
#include <filesystem>
#include <fstream>
#include <random>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* bytes,std::size_t size) {
    if(size>65535)return 0;
    struct Temp {std::filesystem::path path=std::filesystem::temp_directory_path()/("etherscope-file-fuzz-"+std::to_string(std::random_device{}()));~Temp(){std::error_code error;std::filesystem::remove(path,error);}};
    static Temp file;
    try {std::ofstream stream(file.path,std::ios::binary|std::ios::trunc);stream.write(reinterpret_cast<const char*>(bytes),static_cast<std::streamsize>(size));stream.close();etherscope::CaptureReader reader(file.path);for(unsigned i=0;i<4096 && reader.next();++i){}}
    catch(const std::exception&){}
    return 0;
}
