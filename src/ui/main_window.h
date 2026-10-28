#pragma once
#include "capture/capture.h"
#include "capture/export.h"
#include "capture/preparation.h"
#include "capture/details.h"
#include "capture/stream.h"
#include "capture/application_service.h"
#include "capture/recording.h"
#include "ui/packet_model.h"
#include "ui/traffic_chart.h"
#include "ui/source_context.h"
#include "ui/reading_history.h"
#include <QMainWindow>
#include <QElapsedTimer>
#include <QTimer>
#include <QSet>
#include <QPointer>

class QComboBox;
class QLabel;
class QTextEdit;
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
class QToolButton;
class QShowEvent;
class QMenu;
class QDockWidget;

namespace etherscope {
class FilterChip;
class TcpPanel;
class AnalysisDock;
class ApplicationView;
class WindowTitleBar;
class FindBar;
struct MainWindowOptions {
    QString settingsFile;
    QString language;
    CaptureHooks capture;
    ExportWriter exportWriter;
    FilePreparer prepareFile;
    std::function<void(const PacketSnapshot &)> snapshotObserver;
    DetailDecoder detailDecoder;
    StreamDecoder streamDecoder;
    ApplicationHooks application;
    RecordingHooks recording;
};
class MainWindow final : public QMainWindow {
    Q_OBJECT
  public:
    enum class CaptureState { Idle, Starting, Running, Stopping };
    enum class FileOpenResult { Success, Failure, Cancelled };
    Q_ENUM(FileOpenResult)
    explicit MainWindow(QWidget *parent = nullptr, MainWindowOptions options = {});
    ~MainWindow() override;
    bool openFile(const QString &path);
    bool saveFile(const QString &path, std::optional<CaptureFormat> format = {});
    PacketModel *packetModel() const {
        return model_;
    }
    bool busy() const {
        return state_ != CaptureState::Idle || openingFile_;
    }
    bool discovering() const {
        return queryingInterfaces_;
    }
    bool saving() const {
        return saving_;
    }
    bool detailsBusy() const {
        return detailsPending_;
    }
    CaptureState captureState() const {
        return state_;
    }
    CaptureCounters captureCounters() const {
        return engine_.counters();
    }
    const SessionStats &sessionStats() const {
        return view_ == 0 ? live_.stats() : file_.stats();
    }
    std::size_t retainedRawBytes() const {
        return view_ == 0 ? live_.rawBytes() : file_.rawBytes();
    }
    std::size_t retainedEstimatedBytes() const {
        return view_ == 0 ? live_.estimatedBytes() : file_.estimatedBytes();
    }
    const TcpConversations &tcpConversations() const {
        return view_ == 0 ? live_.tcp() : file_.tcp();
    }
    void stopCapture();
    void selectPacket(int row);
    void setDarkTheme(bool dark);
    void ingestBenchmark(std::vector<Packet> packets);
    bool applyExpression(const QString &expression);
    void setTlsKeyLog(const QString &path);
    const ApplicationIndex &applicationIndex() const {
        return applicationIndex_[view_];
    }
    ApplicationServiceStats applicationStats() const {
        return applications_[view_]->stats();
    }
    bool applicationBusy() const {
        return applications_[view_]->busy() || applications_[view_]->stats().pendingUpdates;
    }
    RecordingStats recordingStats() const {
        return recording_.stats();
    }
    bool recordingBusy() const {
        return recordingPending_ || recording_.running();
    }
  signals:
    void saveFinished(bool success, const QString &path, quint64 count, const QString &error);
    void batchProcessed(qint64 microseconds);
    void interfacesFinished(quint64 request);
    void detailsFinished(quint64 request);
    void fileOpenFinished(quint64 request, etherscope::MainWindow::FileOpenResult result,
                          const QString &path, const QString &error);

  protected:
    void closeEvent(QCloseEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void showEvent(QShowEvent *event) override;
    void changeEvent(QEvent *event) override;
    bool nativeEvent(const QByteArray &type, void *message, qintptr *result) override;

  private:
    SessionStore live_, file_;
    WindowTitleBar *titleBar_{};
    void configureNativeFrame();
    PreparationService preparation_;
    CaptureEngine engine_;
    ExportEngine exporter_;
    DetailService details_;
    RecordingService recording_;
    RecordingOptions recordingOptions_;
    ApplicationIndex applicationIndex_[2];
    std::array<std::unique_ptr<ApplicationAnalysisService>, 2> applications_;
    std::uint64_t applicationSubmitted_[2]{};
    QTimer applicationTimer_;
    QLineEdit *expressionInput_{};
    QLabel *expressionError_{};
    QWidget *expressionPanel_{};
    QAction *expressionAction_{}, *recordingAction_{}, *recordingSettingsAction_{};
    QLabel *recordingLabel_{}, *analysisPending_{}, *analysisIncomplete_{};
    std::array<QLabel *, 3> analysisResourceValues_{};
    QDockWidget *diagnosticDock_{};
    std::array<QLabel *, 6> analysisStates_{};
    FilterChip *expressionChip_{};
    QString keyDirectory_;
    std::atomic<bool> recordingSession_{};
    bool recordingPending_{};
    std::unique_ptr<QSettings> settings_;
    PacketModel *model_{};
    QComboBox *devices_{}, *macDirection_{}, *ipDirection_{}, *protocol_{}, *icmpType_{};
    QWidget *icmpTypeGroup_{};
    QLineEdit *mac_{}, *ip_{};
    QPushButton *start_{}, *stop_{}, *open_{}, *save_{};
    QAction *refresh_{}, *theme_{}, *captureFilterAction_{};
    QAction *applicationAction_{};
    QToolButton *expressionToggle_{};
    QWidget *conditionStrip_{}, *emptyState_{};
    QLabel *emptyTitle_{}, *emptyHint_{}, *fieldEmpty_{};
    QPushButton *emptyStart_{}, *emptyOpen_{}, *emptyRefresh_{}, *emptyAdjust_{};
    QLabel *bpfMarker_{};
    QPointer<QDialog> bpfDialog_;
    QPointer<TcpPanel> tcpDialog_;
    QMainWindow *analysisWorkspace_{};
    AnalysisDock *tcpDock_{}, *applicationDock_{};
    ApplicationView *applicationView_{};
    SourceContext tcpContext_, applicationContext_;
    std::uint64_t applicationPacket_{};
    QString sourceNames_[2], tcpSourceName_, applicationSourceName_;
    bool arrangingDocks_{}, tcpInvalidated_{}, applicationInvalidated_{};
    FindBar *find_{};
    ReadingHistory readingHistory_[2];
    QAction *readingBack_{}, *readingForward_{};
    QVariantMap pendingReading_;
    std::optional<std::pair<std::size_t, std::size_t>> findByteRange_;
    void initializeFind();
    QVariantMap readingPosition() const;
    void rememberReading();
    void navigateReading(bool forward);
    void restoreReadingDetails();
    void updateReadingActions();
    struct DisplayState {
        FilterSpec filter;
        QString expression;
        SourceContext source;
        bool operator==(const DisplayState &) const = default;
    };
    std::vector<DisplayState> filterUndo_, filterRecent_;
    bool historyReady_{}, restoringFilter_{};
    QAction *undoFilter_{};
    QMenu *recentFilters_{};
    QTextEdit *fieldHelp_{};
    QWidget *fieldHelpArea_{};
    QPushButton *fieldHelpToggle_{};
    StreamDecoder streamDecoder_;
    QPointer<QLineEdit> bpfInput_;
    QPointer<QPushButton> bpfApply_;
    QString bpfDraft_, successfulBpf_, sessionBpf_, bpfError_;
    LiveCaptureOptions startingOptions_;
    bool liveStarting_{};
    QPushButton *apply_{}, *clear_{};
    QPushButton *addressToggle_{}, *diagnostics_{};
    FilterChip *macChip_{}, *ipChip_{}, *protocolChip_{}, *icmpChip_{}, *conversationChip_{};
    QCheckBox *statistics_{};
    QWidget *chartPanel_{}, *macGroup_{}, *ipGroup_{}, *filterActions_{}, *addressPanel_{},
        *diagnosticPanel_{};
    QGridLayout *filterLayout_{};
    bool compactFilters_{};
    QLabel *status_{}, *macError_{}, *ipError_{};
    QLabel *capturedLabel_{}, *displayedLabel_{}, *droppedLabel_{};
    QLabel *detailId_{}, *detailProtocol_{}, *detailCaptured_{}, *detailOriginal_{},
        *detailIssues_{};
    QList<QLabel *> diagnosticValues_;
    QLabel *exportLabel_{};
    QTableView *table_{};
    QTreeWidget *fields_{};
    QPlainTextEdit *hex_{};
    QWidget *hexPager_{};
    QPushButton *previousBytes_{}, *nextBytes_{};
    QLabel *byteRange_{};
    static constexpr std::size_t hexPageSize_ = 4096;
    std::size_t hexStart_{};
    QTabBar *modes_{};
    QCheckBox *follow_{};
    TrafficChart *chart_{};
    QTimer batchTimer_, rateTimer_;
    QElapsedTimer rateClock_;
    CaptureCounters counters_[2];
    std::string sourceStatus_[2];
    bool failed_[2]{};
    int active_{-1};
    int view_{};
    bool dark_{};
    bool saving_{}, closing_{}, closeScheduled_{}, updatingSelection_{};
    bool openingFile_{}, preparingFile_{}, queryingInterfaces_{}, fileCancelRequested_{};
    quint64 fileRequest_{};
    quint64 activeFileRequest_{};
    QString openingPath_;
    std::function<void(const PacketSnapshot &)> snapshotObserver_;
    bool producerFinished_{}, drainScheduled_{}, snapshotPending_{};
    int snapshotSession_{};
    std::uint64_t snapshotBoundary_{};
    QString snapshotPath_;
    CaptureFormat snapshotFormat_{CaptureFormat::Pcapng};
    QString lastStatusText_;
    bool lastStatusError_{};
    QSet<QString> collapsedFields_;
    CaptureState state_{CaptureState::Idle};
    std::function<void()> pendingAction_;
    QString fileName_, filePath_;
    QString openDirectory_, saveDirectory_, preferredDevice_;
    QString actionError_;
    std::uint64_t lastCount_{}, lastBytes_{};
    std::shared_ptr<const Packet> selected_;
    std::shared_ptr<const PacketDetails> selectedDetails_;
    struct FieldItem {
        QTreeWidgetItem *parent;
        const Field *field;
    };
    std::vector<FieldItem> fieldItems_;
    QTimer detailTimer_;
    quint64 detailRequest_{};
    bool detailsPending_{};
    void fillDetails();
    void refreshInterfaces();
    void startCapture();
    void beginLive(const QString &device, LiveCaptureOptions options);
    void configureCaptureFilter();
    void initializeAnalysis(const MainWindowOptions &options);
    void submitApplications(int session);
    void collectApplications();
    void resetApplications(int session);
    void configureRecording();
    void showApplicationAnalysis();
    void appendDnsFields();
    void showTcpConversations();
    void refreshTcpConversations();
    SourceContext sourceContext(int session) const;
    bool sourceValid(const SourceContext &source, bool analysis = false) const;
    SessionStore &storeFor(int session);
    QString sourceName(int session) const;
    void initializeInteractions();
    void rememberFilter(const FilterSpec &filter, const QString &expression);
    DisplayState displayState() const;
    void restoreFilter(const DisplayState &state);
    void applyQuickFilter(const QString &predicate, bool unique);
    void refreshFilterHistory();
    QMenu *packetMenu(const QModelIndex &index);
    QMenu *fieldMenu(QTreeWidgetItem *item);
    void updateFieldHelp();
    void showExpressionHelp();
    void showAnalysisHelp(AnalysisStatus status);
    AnalysisDock *createAnalysisDock(const QString &title, const QString &name);
    void presentAnalysisDock(AnalysisDock *dock);
    void arrangeAnalysisDocks();
    void saveAnalysisLayout();
    void resetAnalysisLayout();
    void bindTcpSource();
    void bindApplicationSource();
    void refreshAnalysisSources();
    void beginFile(const QString &path, PreparedFile reader);
    void completeFileOpen(FileOpenResult result, const QString &error = {});
    void requestCaptureStop();
    bool scheduleAction(std::function<void()> action);
    void tryClose();
    void flush();
    void finishCapture();
    void startSnapshotExport();
    void buildUi();
    void arrangeFilters();
    void retranslate();
    void switchMode(int index);
    void showMode(int index);
    void restoreSettings();
    void saveSettings();
    void updateFilterStatus();
    void syncFilterInputs();
    void applyFilter();
    void commitFilter(FilterSpec filter);
    void showDetails();
    void renderHexPage(std::size_t start);
    void highlightBytes(QTreeWidgetItem *item, bool locate = true);
    void reportError(const QString &message);
    void updateStatus();
    void updateButtons();
    void updatePresentation();
    SessionStore &currentStore() {
        return view_ == 0 ? live_ : file_;
    }
    void resetRates();
};
} // namespace etherscope
