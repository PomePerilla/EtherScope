#include "capture/preparation.h"
#include "core/pcap_file.h"
#include <filesystem>

namespace etherscope {
PreparationService::PreparationService(QObject* parent,std::function<CaptureInterfaces(QString&)> interfaces,FilePreparer file)
    :QObject(parent),interfaces_(std::move(interfaces)),file_(std::move(file)) {
    qRegisterMetaType<CaptureInterfaces>();qRegisterMetaType<PreparedFile>();
}
PreparationService::~PreparationService() {
    requestStop();if(interfaceWorker_.joinable())interfaceWorker_.join();if(fileWorker_.joinable())fileWorker_.join();
}
bool PreparationService::requestInterfaces() {
    if(discovering_)return false;if(interfaceWorker_.joinable())interfaceWorker_.join();
    const auto request=++interfaceGeneration_;discovering_=true;
    try {interfaceWorker_=std::jthread([this,request](std::stop_token stop){
        CaptureInterfaces interfaces;QString error;
        try {
            if(!stop.stop_requested()) {
                if(interfaces_)interfaces=interfaces_(error);
                else {CaptureEngine independent;interfaces=independent.interfaces(error);}
            }
        } catch(const std::exception& e){error=QString::fromUtf8(e.what());}
        discovering_=false;emit interfacesReady(request,std::move(interfaces),error,stop.stop_requested());
    });} catch(const std::exception& e){discovering_=false;emit interfacesReady(request,{},QString::fromUtf8(e.what()),false);}
    return true;
}
bool PreparationService::requestFile(const QString& path) {
    if(preparingFile_)return false;if(fileWorker_.joinable())fileWorker_.join();
    const auto request=++fileGeneration_;preparingFile_=true;
    try {fileWorker_=std::jthread([this,request,path](std::stop_token stop){
        PreparedFile reader;QString error;
        try {
            if(!stop.stop_requested())reader=file_?file_(path,stop):std::make_shared<PcapReader>(std::filesystem::path(path.toStdWString()));
            if(!reader && !stop.stop_requested())error="文件准备失败";
        }catch(const std::exception& e){error=QString::fromUtf8(e.what());}
        const bool cancelled=stop.stop_requested();if(cancelled)reader.reset();
        preparingFile_=false;emit fileReady(request,path,std::move(reader),error,cancelled);
    });}catch(const std::exception& e){preparingFile_=false;emit fileReady(request,path,{},QString::fromUtf8(e.what()),false);}
    return true;
}
void PreparationService::cancelFile(){if(fileWorker_.joinable())fileWorker_.request_stop();}
void PreparationService::requestStop(){cancelFile();if(interfaceWorker_.joinable())interfaceWorker_.request_stop();}
}
