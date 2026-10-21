#pragma once
#include "capture/capture.h"
#include <QMetaType>

namespace etherscope {
using CaptureInterfaces=std::vector<CaptureInterface>;
using FilePreparer=std::function<PreparedFile(const QString&,std::stop_token)>;
class PreparationService final:public QObject {
    Q_OBJECT
public:
    PreparationService(QObject* parent,std::function<CaptureInterfaces(QString&)> interfaces={},FilePreparer file={});
    ~PreparationService() override;
    bool requestInterfaces();
    bool requestFile(const QString& path);
    void cancelFile();
    void requestStop();
    bool discovering() const {return discovering_;}
    bool preparingFile() const {return preparingFile_;}
    bool busy() const {return discovering_ || preparingFile_;}
    quint64 interfaceGeneration() const {return interfaceGeneration_;}
    quint64 fileGeneration() const {return fileGeneration_;}
signals:
    void interfacesReady(quint64 request,etherscope::CaptureInterfaces interfaces,const QString& error,bool cancelled);
    void fileReady(quint64 request,const QString& path,etherscope::PreparedFile reader,const QString& error,bool cancelled);
private:
    std::function<CaptureInterfaces(QString&)> interfaces_;
    FilePreparer file_;
    std::jthread interfaceWorker_,fileWorker_;
    std::atomic<bool> discovering_{},preparingFile_{};
    quint64 interfaceGeneration_{},fileGeneration_{};
};
}
Q_DECLARE_METATYPE(etherscope::CaptureInterfaces)
Q_DECLARE_METATYPE(etherscope::PreparedFile)
