#include "capture/export.h"
#include "core/pcap_file.h"
#include <QSaveFile>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <ostream>
#include <streambuf>

namespace etherscope {
namespace {
class FileBuffer final:public std::streambuf {
public:
    FileBuffer(QIODevice& file,const ExportWriter& writer,std::function<void(quint64)> progress)
        :file_(file),writer_(writer),progress_(std::move(progress)) {setp(buffer_.data(),buffer_.data()+buffer_.size());}
protected:
    int sync() override {
        const auto pending=pptr()-pbase();qint64 written=0;
        while(written<pending) {
            const auto n=writer_?writer_(file_,pbase()+written,pending-written):file_.write(pbase()+written,pending-written);
            if(n<=0 || n>pending-written) return -1;written+=n;bytes_+=static_cast<quint64>(n);progress_(bytes_);
        }
        pbump(-static_cast<int>(pending));return 0;
    }
    int_type overflow(int_type ch) override {
        if(sync()!=0) return traits_type::eof();
        if(!traits_type::eq_int_type(ch,traits_type::eof())) {*pptr()=traits_type::to_char_type(ch);pbump(1);}
        return traits_type::not_eof(ch);
    }
    std::streamsize xsputn(const char* data,std::streamsize count) override {
        std::streamsize copied=0;
        while(copied<count) {
            if(pptr()==epptr() && sync()!=0) break;
            const auto n=std::min<std::streamsize>(epptr()-pptr(),count-copied);
            std::memcpy(pptr(),data+copied,static_cast<std::size_t>(n));pbump(static_cast<int>(n));copied+=n;
        }
        return copied;
    }
private:
    QIODevice& file_;
    const ExportWriter& writer_;
    std::function<void(quint64)> progress_;
    std::array<char,64*1024> buffer_{};
    quint64 bytes_{};
};
}
ExportEngine::ExportEngine(QObject* parent,ExportWriter writer):QObject(parent),writer_(std::move(writer)) {}
ExportEngine::~ExportEngine() {if(worker_.joinable()) worker_.join();}
bool ExportEngine::start(const QString& path,PacketSnapshot snapshot) {
    if(running_ || snapshot.empty() || path.isEmpty()) return false;
    if(worker_.joinable()) worker_.join();
    const auto job=++generation_;running_=true;
    std::size_t footprint=0;for(const auto& packet:snapshot)if(packet)footprint+=packet->estimatedBytes?packet->estimatedBytes:estimatePacketBytes(*packet);
    referencedBytes_=footprint;
    try {worker_=std::jthread([this,job,path,snapshot=std::move(snapshot)]() mutable {
        QString error;bool success=false;const auto count=static_cast<quint64>(snapshot.size());
        try {
            quint64 total=24;std::vector<const Packet*> packets;packets.reserve(snapshot.size());
            for(const auto& p:snapshot) {packets.push_back(p.get());if(p) total+=16+p->raw.bytes.size();}
            QSaveFile file(path);file.setDirectWriteFallback(false);
            if(!file.open(QIODevice::WriteOnly)) throw std::runtime_error("文件保存失败");
            auto last=std::chrono::steady_clock::now();emit progress(job,0,total);
            FileBuffer buffer(file,writer_,[&](quint64 bytes){
                const auto now=std::chrono::steady_clock::now();
                if(now-last>=std::chrono::milliseconds(100)) {emit progress(job,bytes,total);last=now;}
            });
            std::ostream stream(&buffer);writePcap(stream,packets);stream.flush();
            if(!stream || !file.commit()) throw std::runtime_error("文件保存失败");
            success=true;
        } catch(const std::exception& e) {error=QString::fromUtf8(e.what());}
        // Release references to evicted cache records before publishing completion.
        snapshot.clear();referencedBytes_=0;running_=false;emit finished(job,success,path,count,error);
    });} catch(const std::exception&) {referencedBytes_=0;running_=false;return false;}
    return true;
}
}
