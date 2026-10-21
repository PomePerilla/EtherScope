#include "capture/recording.h"
#include "capture/file_buffer.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QUuid>
#include <ostream>
#include <sstream>

namespace etherscope {
RecordingService::RecordingService(QObject* parent,RecordingHooks hooks):QObject(parent),hooks_(std::move(hooks)){}
RecordingService::~RecordingService(){finish();if(thread_.joinable())thread_.join();}
RecordingStats RecordingService::stats() const {std::lock_guard lock(mutex_);auto value=stats_;value.queued=queue_.size();return value;}
bool RecordingService::start(RecordingOptions options) {
    if(running_ || !options.enabled || options.directory.isEmpty() || options.fileBytes<256 || options.fileBytes>UINT64_MAX/2 || options.diskBytes<2*options.fileBytes || !options.durationMs)return false;
    if(thread_.joinable())thread_.join();
    {std::lock_guard lock(mutex_);queue_.clear();queueBytes_=0;stats_={};stats_.directory=QDir(options.directory).absoluteFilePath("capture-"+QUuid::createUuid().toString(QUuid::WithoutBraces));accepting_=true;finishing_=false;}
    const auto request=++generation_;running_=true;
    try{thread_=std::jthread([this,options,request]{run(options,request);});}
    catch(const std::exception& error){running_=false;std::lock_guard lock(mutex_);accepting_=false;stats_.failed=true;stats_.error=QString::fromUtf8(error.what());return false;}
    return true;
}
void RecordingService::submit(const RawPacket& raw) {
    std::lock_guard lock(mutex_);
    if(!accepting_){if(stats_.failed)++stats_.unwritten;return;}
    const auto bytes=raw.bytes.size();
    if(queue_.size()>=8192 || bytes>32*1024*1024 || queueBytes_>32*1024*1024-bytes){accepting_=false;finishing_=true;stats_.failed=true;stats_.error="Recording queue limit reached";++stats_.unwritten;wake_.notify_one();return;}
    queue_.push_back(raw);queueBytes_+=bytes;wake_.notify_one();
}
void RecordingService::finish(){std::lock_guard lock(mutex_);accepting_=false;finishing_=true;wake_.notify_one();}
void RecordingService::run(RecordingOptions options,quint64 request) {
    struct Closed {QString path;std::uint64_t bytes;};std::deque<Closed> files;std::uint64_t closedBytes=0,totalClosedBytes=0,pending=0;bool current=false;
    const auto directory=stats().directory;QString active;QFile file;std::unique_ptr<FileBuffer> buffer;std::unique_ptr<std::ostream> stream;std::unique_ptr<CaptureWriter> writer;
    auto now=[this]{return hooks_.now?hooks_.now():std::chrono::steady_clock::now();};auto created=now(),lastFlush=created;unsigned sequence=0;
    auto manifest=[&]{
        QJsonArray names;for(const auto& item:files)names.append(QFileInfo(item.path).fileName());
        QJsonObject object;object["files"]=names;if(!active.isEmpty())object["active"]=QFileInfo(active).fileName();
        QSaveFile out(QDir(directory).filePath("files.json"));out.setDirectWriteFallback(false);const auto data=QJsonDocument(object).toJson(QJsonDocument::Compact);
        if(!out.open(QIODevice::WriteOnly) || out.write(data)!=data.size() || !out.commit())throw std::runtime_error("Recording manifest write failed");
    };
    auto flush=[&]{if(!stream)return;stream->flush();if(!*stream || !file.flush())throw std::runtime_error("Recording write failed");std::lock_guard lock(mutex_);stats_.written+=pending;pending=0;stats_.diskBytes=closedBytes+writer->bytesWritten();lastFlush=now();};
    auto close=[&]{
        if(!writer)return;flush();const auto bytes=writer->bytesWritten();writer.reset();stream.reset();buffer.reset();file.close();
        const auto final=active.left(active.size()-5);if(!QFile::rename(active,final))throw std::runtime_error("Recording finalization failed");files.push_back({final,bytes});closedBytes+=bytes;totalClosedBytes+=bytes;active.clear();manifest();
    };
    auto room=[&](std::uint64_t required){
        while(closedBytes+(writer?writer->bytesWritten():0)>options.diskBytes-required) {
            if(files.empty())throw std::runtime_error("Recording disk limit reached");const auto oldest=files.front();
            if(QFileInfo(oldest.path).absolutePath()!=QDir(directory).absolutePath() || !(hooks_.remove?hooks_.remove(oldest.path):QFile::remove(oldest.path)))throw std::runtime_error("Recording file removal failed");
            closedBytes-=oldest.bytes;files.pop_front();manifest();
        }
    };
    try {
        for(;;) {
            std::optional<RawPacket> packet;
            {
                std::unique_lock lock(mutex_);wake_.wait_for(lock,std::chrono::milliseconds(100),[this]{return finishing_ || !queue_.empty();});
                if(!queue_.empty()){packet=std::move(queue_.front());queue_.pop_front();queueBytes_-=packet->bytes.size();current=true;}
                else if(finishing_)break;
            }
            if(!packet){if(now()-lastFlush>=std::chrono::seconds(1))flush();continue;}
            const auto recordBytes=32u+((packet->bytes.size()+3)&~std::size_t(3));
            if(recordBytes+128>options.fileBytes)throw std::runtime_error("Recording packet exceeds file limit");
            if(writer && (writer->bytesWritten()+recordBytes>options.fileBytes || now()-created>=std::chrono::milliseconds(options.durationMs)))close();
            if(!writer) {
                if(!QDir().mkpath(directory))throw std::runtime_error("Recording directory creation failed");
                const RawPacket* descriptor=&*packet;std::ostringstream header;CaptureWriter preview(header,CaptureFormat::Pcapng,std::span(&descriptor,1));
                if(preview.bytesWritten()+recordBytes>options.fileBytes)throw std::runtime_error("Recording packet exceeds file limit");room(recordBytes+preview.bytesWritten());
                active=QDir(directory).filePath(QString("capture-%1.pcapng.part").arg(++sequence,6,10,QChar('0')));file.setFileName(active);
                if(!file.open(QIODevice::WriteOnly|QIODevice::NewOnly))throw std::runtime_error("Recording file open failed");
                buffer=std::make_unique<FileBuffer>(file,hooks_.write,[&](quint64 bytes){std::lock_guard lock(mutex_);stats_.bytesWritten=totalClosedBytes+bytes;});stream=std::make_unique<std::ostream>(buffer.get());
                writer=std::make_unique<CaptureWriter>(*stream,CaptureFormat::Pcapng,std::span(&descriptor,1));created=now();manifest();
            }
            room(recordBytes);writer->write(*packet);++pending;current=false;
            if(now()-lastFlush>=std::chrono::seconds(1))flush();
        }
        flush();if(!stats().failed)close();else {writer.reset();stream.reset();buffer.reset();file.close();}
    } catch(const std::exception& error) {
        writer.reset();stream.reset();buffer.reset();file.close();
        std::lock_guard lock(mutex_);stats_.failed=true;stats_.error=QString::fromUtf8(error.what());stats_.unwritten+=queue_.size()+pending+(current?1u:0u);queue_.clear();queueBytes_=0;accepting_=false;
    }
    const auto final=stats();running_=false;emit finished(request,!final.failed,final.error);
}
}
