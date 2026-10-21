#include "ui/main_window.h"
#include "version.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QFont>
#include <QStyleFactory>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

int main(int argc,char** argv) {
#ifdef _WIN32
    struct RunningMarker {
        HANDLE handle=CreateMutexW(nullptr,FALSE,L"EtherScope.Desktop");
        ~RunningMarker(){if(handle)CloseHandle(handle);}
    } runningMarker;
#endif
    QApplication app(argc,argv);app.setApplicationName("EtherScope");app.setApplicationVersion(ETHERSCOPE_VERSION);
    app.setOrganizationName("EtherScope Course Project");app.setStyle(QStyleFactory::create("Fusion"));
    app.setFont(QFont("Microsoft YaHei UI",10));
    QCommandLineParser parser;parser.setApplicationDescription("EtherScope Windows 协议分析器");parser.addHelpOption();parser.addVersionOption();
    QCommandLineOption open({"o","open"},"打开 Ethernet PCAP 文件","path");parser.addOption(open);
    QCommandLineOption settings("settings-file","使用指定的设置文件","path");parser.addOption(settings);parser.process(app);
    etherscope::MainWindowOptions options;if(parser.isSet(settings))options.settingsFile=parser.value(settings);
    etherscope::MainWindow window(nullptr,std::move(options));window.show();if(parser.isSet(open)) window.openFile(parser.value(open));return app.exec();
}
