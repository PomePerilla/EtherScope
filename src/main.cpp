#include "ui/main_window.h"
#include "ui/language.h"
#include "version.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QFont>
#include <QFontDatabase>
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
    auto font=QFontDatabase::systemFont(QFontDatabase::GeneralFont);font.setPointSize(10);app.setFont(font);
    QCommandLineParser parser;parser.setApplicationDescription("EtherScope Windows protocol analyzer");parser.addHelpOption();parser.addVersionOption();
    QCommandLineOption open({"o","open"},"Open an Ethernet PCAP file","path");parser.addOption(open);
    QCommandLineOption settings("settings-file","Use a settings file","path");parser.addOption(settings);
    QCommandLineOption language("language","Interface language: en, zh-CN, zh-TW","code");parser.addOption(language);parser.process(app);
    etherscope::MainWindowOptions options;if(parser.isSet(settings))options.settingsFile=parser.value(settings);options.language="auto";
    if(parser.isSet(language)){options.language=etherscope::i18n::normalize(parser.value(language));if(options.language.isEmpty())parser.showHelp(2);}
    etherscope::MainWindow window(nullptr,std::move(options));window.show();if(parser.isSet(open)) window.openFile(parser.value(open));return app.exec();
}
