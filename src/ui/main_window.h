#pragma once
#include "capture/capture.h"
#include "capture/export.h"
#include "capture/preparation.h"
#include "capture/details.h"
#include "ui/packet_model.h"
#include "ui/traffic_chart.h"
#include <QMainWindow>
#include <QElapsedTimer>
#include <QTimer>
#include <QSet>
#include <QPointer>

class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTableView;
class QTreeWidget;
class QTreeWidgetItem;
class QTabBar;
class QCheckBox;
class QAction;

class QSettings;
class QCloseEvent;
class QResizeEvent;
class QGridLayout;
class QDialog;

namespace etherscope {
class FilterChip;
struct MainWindowOptions {
    QString settingsFile;
    CaptureHooks capture;
    ExportWriter exportWriter;
    FilePreparer prepareFile;
    std::function<void(const PacketSnapshot&)> snapshotObserver;
    DetailDecoder detailDecoder;
};
class MainWindow final:public QMainWindow {
    Q_OBJECT
public:
    enum class CaptureState {Idle,Starting,Running,Stopping};
    enum class FileOpenResult {Success,Failure,Cancelled};
    Q_ENUM(FileOpenResult)
    explicit MainWindow(QWidget* parent=nullptr,MainWindowOptions options={});
    ~MainWindow() override;
    bool openFile(const QString& path);
    bool saveFile(const QString& path);
    PacketModel* packetModel() const { return model_; }
    bool busy() const { return state_!=CaptureState::Idle || openingFile_; }
    bool discovering() const {return queryingInterfaces_;}
    bool saving() const {return saving_;}
    bool detailsBusy() const {return detailsPending_;}
    CaptureState captureState() const {return state_;}
    CaptureCounters captureCounters() const {return engine_.counters();}
    const SessionStats& sessionStats() const {return view_==0?live_.stats():file_.stats();}
    std::size_t retainedRawBytes() const {return view_==0?live_.rawBytes():file_.rawBytes();}
    std::size_t retainedEstimatedBytes() const {return view_==0?live_.estimatedBytes():file_.estimatedBytes();}
    void stopCapture();
    void selectPacket(int row);
    void setDarkTheme(bool dark);
    void ingestBenchmark(std::vector<Packet> packets);
signals:
    void saveFinished(bool success,const QString& path,quint64 count,const QString& error);
    void batchProcessed(qint64 microseconds);
    void interfacesFinished(quint64 request);
    void detailsFinished(quint64 request);
    void fileOpenFinished(quint64 request,etherscope::MainWindow::FileOpenResult result,const QString& path,const QString& error);
protected:
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* watched,QEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
private:
    SessionStore live_,file_;
    PreparationService preparation_;
    CaptureEngine engine_;
    ExportEngine exporter_;
    DetailService details_;
    std::unique_ptr<QSettings> settings_;
    PacketModel* model_{};
    QComboBox *devices_{},*macDirection_{},*ipDirection_{},*protocol_{},*icmpType_{};
    QWidget* icmpTypeGroup_{};
    QLineEdit *mac_{},*ip_{};
    QPushButton *start_{},*stop_{},*open_{},*save_{};
    QAction *refresh_{},*theme_{},*captureFilterAction_{};
    QLabel* bpfMarker_{};
    QPointer<QDialog> bpfDialog_;
    QPointer<QLineEdit> bpfInput_;
    QPointer<QPushButton> bpfApply_;
    QString bpfDraft_,successfulBpf_,sessionBpf_,bpfError_;
    LiveCaptureOptions startingOptions_;
    bool liveStarting_{};
    QPushButton *apply_{},*clear_{};
    QPushButton *addressToggle_{},*diagnostics_{};
    FilterChip *macChip_{},*ipChip_{},*protocolChip_{},*icmpChip_{};
    QCheckBox* statistics_{};
    QWidget *chartPanel_{},*macGroup_{},*ipGroup_{},*filterActions_{},*addressPanel_{},*diagnosticPanel_{};
    QGridLayout* filterLayout_{};
    bool compactFilters_{};
    QLabel *status_{},*macError_{},*ipError_{};
    QLabel *capturedLabel_{},*displayedLabel_{},*droppedLabel_{};
    QLabel *detailId_{},*detailProtocol_{},*detailCaptured_{},*detailOriginal_{},*detailIssues_{};
    QList<QLabel*> diagnosticValues_;
    QLabel* exportLabel_{};
    QTableView* table_{};
    QTreeWidget* fields_{};
    QPlainTextEdit* hex_{};
    QWidget* hexPager_{};
    QPushButton *previousBytes_{},*nextBytes_{};
    QLabel* byteRange_{};
    static constexpr std::size_t hexPageSize_=4096;
    std::size_t hexStart_{};
    QTabBar* modes_{};
    QCheckBox* follow_{};
    TrafficChart* chart_{};
    QTimer batchTimer_,rateTimer_;
    QElapsedTimer rateClock_;
    CaptureCounters counters_[2];
    std::string sourceStatus_[2];
    bool failed_[2]{};
    int active_{-1};
    int view_{};
    bool dark_{};
    bool saving_{},closing_{},closeScheduled_{},updatingSelection_{};
    bool openingFile_{},preparingFile_{},queryingInterfaces_{},fileCancelRequested_{};
    quint64 fileRequest_{};
    quint64 activeFileRequest_{};
    QString openingPath_;
    std::function<void(const PacketSnapshot&)> snapshotObserver_;
    bool producerFinished_{},drainScheduled_{},snapshotPending_{};
    int snapshotSession_{};
    std::uint64_t snapshotBoundary_{};
    QString snapshotPath_;
    QString lastStatusText_;
    bool lastStatusError_{};
    QSet<QString> collapsedFields_;
    CaptureState state_{CaptureState::Idle};
    std::function<void()> pendingAction_;
    QString fileName_,filePath_;
    QString openDirectory_,saveDirectory_,preferredDevice_;
    QString actionError_;
    std::uint64_t lastCount_{},lastBytes_{};
    std::shared_ptr<const Packet> selected_;
    std::shared_ptr<const PacketDetails> selectedDetails_;
    struct FieldItem {QTreeWidgetItem* parent;const Field* field;};
    std::vector<FieldItem> fieldItems_;
    QTimer detailTimer_;
    quint64 detailRequest_{};
    bool detailsPending_{};
    void fillDetails();
    void refreshInterfaces();
    void startCapture();
    void beginLive(const QString& device,LiveCaptureOptions options);
    void configureCaptureFilter();
    void beginFile(const QString& path,PreparedFile reader);
    void completeFileOpen(FileOpenResult result,const QString& error={});
    void requestCaptureStop();
    bool scheduleAction(std::function<void()> action);
    void tryClose();
    void flush();
    void finishCapture();
    void startSnapshotExport();
    void buildUi();
    void arrangeFilters();
    void switchMode(int index);
    void showMode(int index);
    void restoreSettings();
    void saveSettings();
    void updateFilterStatus();
    void applyFilter();
    void commitFilter(FilterSpec filter);
    void showDetails();
    void renderHexPage(std::size_t start);
    void highlightBytes(QTreeWidgetItem* item,bool locate=true);
    void reportError(const QString& message);
    void updateStatus();
    void updateButtons();
    SessionStore& currentStore() { return view_==0?live_:file_; }
    void resetRates();
};
}
