#include "core/application.h"
#include "core/application_stream.h"
#include "core/display_filter.h"
#include "core/tls.h"
#include <cstdlib>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* bytes,std::size_t size) {
    using namespace etherscope;if(!size || size>65535)return 0;
    ApplicationInput input;input.bytes=std::make_shared<const std::vector<std::uint8_t>>(bytes+1,bytes+size);input.sources={{1,0,size-1,0}};input.startKnown=input.endKnown=true;
    ApplicationResult result;
    switch(bytes[0]%5){case 0:result=decodeDns(input);break;case 1:result=decodeHttp1({input,{}});break;case 2:result=decodeHttp2({input,{}});break;case 3:{TlsKeyLog keys;result=decodeTls({input,{}},keys).analysis;break;}default:{const auto filter=compileDisplayFilter(std::string_view(reinterpret_cast<const char*>(bytes+1),size-1));if(filter.value){Packet p;filter.value->evaluate(p);}return 0;}}
    if (bytes[0] % 5 >= 1 && bytes[0] % 5 <= 3) {
        Http1Stream http1;
        Http2Stream http2;
        TlsStream tls;
        TlsKeyLog keys;
        for (std::size_t cursor = 1; cursor < size;) {
            const auto count = std::min<std::size_t>(1 + bytes[cursor] % 127, size - cursor);
            ApplicationInput part;
            part.bytes = std::make_shared<const std::vector<std::uint8_t>>(bytes + cursor, bytes + cursor + count);
            part.sources = {{cursor, 0, count, 0}};
            part.startKnown = true;
            part.endKnown = cursor + count == size;
            result = bytes[0] % 5 == 1 ? http1.append({part, {}}) :
                     bytes[0] % 5 == 2 ? http2.append({part, {}}) :
                     tls.append({part, {}}, keys).analysis;
            cursor += count;
        }
    }
    if(result.messages.size()>4096)std::abort();
    for(const auto& m:result.messages){if(!m.bytes || m.offset>m.bytes->size() || m.length>m.bytes->size()-m.offset || m.fields.size()>maxPacketFields)std::abort();for(const auto& f:m.fields)if(f.offset>m.bytes->size() || f.length>m.bytes->size()-f.offset)std::abort();}
    return 0;
}
