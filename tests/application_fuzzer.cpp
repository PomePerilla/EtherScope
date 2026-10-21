#include "core/application.h"
#include "core/display_filter.h"
#include "core/tls.h"
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* bytes,std::size_t size) {
    using namespace etherscope;if(!size || size>65535)return 0;
    ApplicationInput input;input.bytes=std::make_shared<const std::vector<std::uint8_t>>(bytes+1,bytes+size);input.sources={{1,0,size-1,0}};input.startKnown=input.endKnown=true;
    ApplicationResult result;
    switch(bytes[0]%5){case 0:result=decodeDns(input);break;case 1:result=decodeHttp1({input,{}});break;case 2:result=decodeHttp2({input,{}});break;case 3:{TlsKeyLog keys;result=decodeTls({input,{}},keys).analysis;break;}default:{const auto filter=compileDisplayFilter(std::string_view(reinterpret_cast<const char*>(bytes+1),size-1));if(filter.value){Packet p;filter.value->evaluate(p);}return 0;}}
    if(result.messages.size()>4096)std::abort();
    for(const auto& m:result.messages){if(!m.bytes || m.offset>m.bytes->size() || m.length>m.bytes->size()-m.offset || m.fields.size()>maxPacketFields)std::abort();for(const auto& f:m.fields)if(f.offset>m.bytes->size() || f.length>m.bytes->size()-f.offset)std::abort();}
    return 0;
}
