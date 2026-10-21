#include "core/application.h"
#include "core/bytes.h"
#include <nghttp2/nghttp2.h>
#include <algorithm>
#include <charconv>
#include <set>

namespace etherscope {
namespace {
constexpr std::string_view preface="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
struct Frame {unsigned side;std::size_t offset,length;std::uint32_t stream;std::uint8_t type,flags;std::uint64_t packet;};
struct Inflater {
    nghttp2_hd_inflater* value{};
    Inflater(){if(nghttp2_hd_inflate_new(&value))throw std::runtime_error("HPACK initialization failed");}
    ~Inflater(){nghttp2_hd_inflate_del(value);}
    Inflater(const Inflater&)=delete;
    Inflater& operator=(const Inflater&)=delete;
};
struct Headers {std::vector<std::uint8_t> bytes;std::uint32_t stream{};std::size_t message{},offset{};bool open{};};
void add(ApplicationMessage& m,std::string name,std::string key,ApplicationValue value,std::size_t offset,std::size_t length){if(m.fields.size()>=applicationHeaderCount+8)throw std::length_error("HTTP/2 header limit reached");m.fields.push_back({std::move(name),std::move(key),std::move(value),offset,length});}
void inflate(Inflater& inflater,Headers& headers,ApplicationMessage& m,std::size_t end) {
    auto bytes=std::span<const std::uint8_t>(headers.bytes);std::size_t total=0;bool regular=false;std::set<std::string> pseudo;
    for(;;) {
        nghttp2_nv nv{};int flags=0;const auto consumed=nghttp2_hd_inflate_hd3(inflater.value,&nv,&flags,bytes.data(),bytes.size(),1);
        if(consumed<0 || static_cast<std::size_t>(consumed)>bytes.size())throw std::runtime_error("Invalid HPACK block");bytes=bytes.subspan(static_cast<std::size_t>(consumed));
        if(flags&NGHTTP2_HD_INFLATE_EMIT) {
            total+=nv.namelen+nv.valuelen;if(total>applicationHeaderLimit)throw std::length_error("HTTP/2 header limit reached");
            std::string name(reinterpret_cast<char*>(nv.name),nv.namelen),value(reinterpret_cast<char*>(nv.value),nv.valuelen);
            if(name.empty() || std::any_of(name.begin(),name.end(),[](unsigned char c){return c<33 || c>126 || (c>='A' && c<='Z');}) || std::any_of(value.begin(),value.end(),[](unsigned char c){return c==0 || c=='\r' || c=='\n';}))throw std::runtime_error("Invalid HTTP/2 header");
            if(name[0]==':'){if(regular || !pseudo.insert(name).second)throw std::runtime_error("Invalid HTTP/2 pseudo-header order");}else regular=true;
            if(name=="connection" || name=="proxy-connection" || name=="keep-alive" || name=="transfer-encoding" || name=="upgrade" || (name=="te" && value!="trailers"))throw std::runtime_error("Invalid HTTP/2 connection header");
            if(name[0]==':' && name!=":method" && name!=":scheme" && name!=":path" && name!=":authority" && name!=":status" && name!=":protocol")throw std::runtime_error("Unknown HTTP/2 pseudo-header");
            if(pseudo.contains(":status") && pseudo.size()>1)throw std::runtime_error("Mixed HTTP/2 pseudo-headers");
            std::string key="http.header."+name;ApplicationValue fieldValue=value;
            if(name==":method")key="http.request.method";else if(name==":path")key="http.request.uri";else if(name==":authority" || name=="host")key="http.host";
            else if(name==":status"){std::uint64_t status=0;auto [p,e]=std::from_chars(value.data(),value.data()+value.size(),status);if(e!=std::errc{} || p!=value.data()+value.size() || value.size()!=3 || status<100)throw std::runtime_error("Invalid HTTP/2 status");key="http.response.code";fieldValue=status;}
            add(m,name,key,std::move(fieldValue),headers.offset,end-headers.offset);
        }
        if(flags&NGHTTP2_HD_INFLATE_FINAL){if(!bytes.empty())throw std::runtime_error("HPACK trailing data");nghttp2_hd_inflate_end_headers(inflater.value);break;}
        if(!consumed && !(flags&NGHTTP2_HD_INFLATE_EMIT))throw std::runtime_error("Incomplete HPACK block");
    }
}
}
ApplicationResult decodeHttp2(const std::array<ApplicationInput,2>& input,std::stop_token stop) {
    ApplicationResult result;
    try {
        std::vector<Frame> frames;std::optional<unsigned> client;
        for(unsigned side=0;side<2;++side) {
            if(!input[side].bytes)continue;const auto& data=*input[side].bytes;ByteView view(data);std::size_t cursor=0;
            if(data.size()>=preface.size() && std::equal(preface.begin(),preface.end(),data.begin())){if(client)throw std::runtime_error("Duplicate HTTP/2 preface");client=side;cursor=preface.size();}
            if(!input[side].startKnown){result.status=AnalysisStatus::Incomplete;return result;}
            bool first=true;
            while(cursor<data.size()) {
                if(stop.stop_requested())return result;
                if(frames.size()>=2048)throw std::length_error("HTTP/2 frame limit reached");
                if(!containsBytes(data.size(),cursor,9)){result.status=AnalysisStatus::Incomplete;result.error="Incomplete HTTP/2 frame";break;}
                const auto n=static_cast<std::size_t>(view.integer(cursor,3));if(!containsBytes(data.size(),cursor+9,n)){result.status=AnalysisStatus::Incomplete;result.error="Incomplete HTTP/2 frame";break;}
                Frame frame{side,cursor,n,static_cast<std::uint32_t>(view.integer(cursor+5,4)&0x7fffffff),data[cursor+3],data[cursor+4],0};
                if(first && (frame.type!=4 || frame.flags&1))throw std::runtime_error("HTTP/2 SETTINGS expected");first=false;
                const auto sources=messageSources(input[side],cursor,n+9);for(const auto& source:sources)frame.packet=std::max(frame.packet,source.packetId);
                frames.push_back(frame);cursor+=9+n;
            }
        }
        if(!client){result.status=AnalysisStatus::Incomplete;result.error="HTTP/2 preface is missing";return result;}
        std::stable_sort(frames.begin(),frames.end(),[](const auto& a,const auto& b){return a.packet<b.packet;});
        std::array<Inflater,2> inflaters;std::array<Headers,2> headers;
        std::array<std::uint32_t,2> maxFrame{16384,16384};
        std::set<std::uint32_t> streams;
        for(const auto& frame:frames) {
            if(stop.stop_requested())return result;const auto& source=input[frame.side];const auto& data=*source.bytes;ByteView view(data);auto& pending=headers[frame.side];
            if(frame.length>maxFrame[frame.side])throw std::runtime_error("HTTP/2 frame exceeds negotiated size");
            if(pending.open && (frame.type!=9 || pending.stream!=frame.stream))throw std::runtime_error("HTTP/2 CONTINUATION expected");
            if(result.messages.size()>=1024)throw std::length_error("HTTP/2 message limit reached");
            ApplicationMessage m;m.protocol="HTTP2";m.direction=frame.side;m.streamId=frame.stream;m.source=source.source;m.bytes=source.bytes;m.offset=frame.offset;m.length=frame.length+9;m.sources=messageSources(source,m.offset,m.length);m.summary="Frame "+std::to_string(frame.type)+" stream "+std::to_string(frame.stream);
            add(m,"Frame type","http2.type",std::uint64_t(frame.type),frame.offset+3,1);add(m,"Stream","http2.streamid",std::uint64_t(frame.stream),frame.offset+5,4);
            auto begin=frame.offset+9,end=begin+frame.length;
            if(frame.type==0 || frame.type==1 || frame.type==5) {
                if(!frame.stream)throw std::runtime_error("HTTP/2 stream ID is zero");
                if(frame.flags&8){const auto padding=view.integer(begin++,1);if(begin>end || padding>end-begin)throw std::runtime_error("Invalid HTTP/2 padding");end-=static_cast<std::size_t>(padding);}
            }
            if(frame.type==1 || frame.type==5) {
                if(streams.size()>=1024 && !streams.contains(frame.stream))throw std::length_error("HTTP/2 stream limit reached");streams.insert(frame.stream);
                if(frame.type==1 && frame.flags&32){if(end-begin<5 || (view.integer(begin,4)&0x7fffffff)==frame.stream)throw std::runtime_error("Invalid HTTP/2 priority");begin+=5;}
                if(frame.type==5){if(end-begin<4 || !(view.integer(begin,4)&0x7fffffff))throw std::runtime_error("Invalid HTTP/2 promised stream");m.streamId=static_cast<std::uint32_t>(view.integer(begin,4)&0x7fffffff);begin+=4;}
                pending={};pending.stream=frame.stream;pending.message=result.messages.size();pending.offset=begin;pending.open=true;
            }
            if(frame.type==1 || frame.type==5 || frame.type==9) {
                if(!pending.open || pending.stream!=frame.stream)throw std::runtime_error("Unexpected HTTP/2 CONTINUATION");
                if(end-begin>applicationHeaderLimit-pending.bytes.size())throw std::length_error("HTTP/2 header limit reached");const auto part=view.slice(begin,end-begin);pending.bytes.insert(pending.bytes.end(),part.begin(),part.end());
                if(frame.flags&4){
                    auto& target=frame.type==9?result.messages[pending.message]:m;inflate(inflaters[frame.side],pending,target,end);
                    if(frame.type==9){target.sources.insert(target.sources.end(),m.sources.begin(),m.sources.end());target.length=end-target.offset;}
                    pending.open=false;pending.bytes.clear();
                }
            } else if(frame.type==2) {if(!frame.stream || frame.length!=5 || (view.integer(begin,4)&0x7fffffff)==frame.stream)throw std::runtime_error("Invalid HTTP/2 PRIORITY");}
            else if(frame.type==3) {if(!frame.stream || frame.length!=4)throw std::runtime_error("Invalid HTTP/2 RST_STREAM");add(m,"Error code","http2.error",view.integer(begin,4),begin,4);}
            else if(frame.type==4) {
                if(frame.stream || frame.length%6 || ((frame.flags&1) && frame.length))throw std::runtime_error("Invalid HTTP/2 SETTINGS");
                for(auto at=begin;at<end;at+=6){const auto key=view.integer(at,2),value=view.integer(at+2,4);
                    if(key==1){if(value>65536)throw std::length_error("HPACK table limit reached");if(nghttp2_hd_inflate_change_table_size(inflaters[1-frame.side].value,static_cast<std::size_t>(value)))throw std::runtime_error("Invalid HPACK table size");}
                    else if(key==2 && value>1)throw std::runtime_error("Invalid HTTP/2 ENABLE_PUSH");
                    else if(key==4 && value>0x7fffffff)throw std::runtime_error("Invalid HTTP/2 window size");
                    else if(key==5){if(value<16384 || value>16777215)throw std::runtime_error("Invalid HTTP/2 maximum frame size");maxFrame[1-frame.side]=static_cast<std::uint32_t>(value);}
                }
            } else if(frame.type==6) {if(frame.stream || frame.length!=8)throw std::runtime_error("Invalid HTTP/2 PING");}
            else if(frame.type==7) {if(frame.stream || frame.length<8)throw std::runtime_error("Invalid HTTP/2 GOAWAY");add(m,"Error code","http2.error",view.integer(begin+4,4),begin+4,4);}
            else if(frame.type==8) {if(frame.length!=4 || !(view.integer(begin,4)&0x7fffffff))throw std::runtime_error("Invalid HTTP/2 WINDOW_UPDATE");}
            result.messages.push_back(std::move(m));
        }
        for(unsigned side=0;side<2;++side)if(headers[side].open || input[side].incomplete)result.status=AnalysisStatus::Incomplete;
    } catch(const std::length_error& e){result.status=AnalysisStatus::Limited;result.error=e.what();}
    catch(const std::exception& e){result.status=AnalysisStatus::Incomplete;result.error=e.what();}
    return result;
}
}
