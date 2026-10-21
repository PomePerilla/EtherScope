#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <pcap/pcap.h>
#endif
#include "capture/capture.h"
#include "core/pcap_file.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <stdexcept>

namespace etherscope {
struct CaptureEngine::Api {
#ifdef _WIN32
    HMODULE module{};
    decltype(&pcap_findalldevs) findAll{};
    decltype(&pcap_freealldevs) freeAll{};
    decltype(&pcap_open_live) openLive{};
    decltype(&pcap_close) close{};
    decltype(&pcap_datalink) datalink{};
    decltype(&pcap_setnonblock) setNonblock{};
    decltype(&pcap_next_ex) next{};
    decltype(&pcap_stats) stats{};
    decltype(&pcap_getevent) getEvent{};
    decltype(&pcap_setmintocopy) setMinToCopy{};
    decltype(&pcap_geterr) getError{};
    decltype(&pcap_compile) compile{};
    decltype(&pcap_setfilter) setFilter{};
    decltype(&pcap_freecode) freeCode{};
    decltype(&pcap_lookupnet) lookupNet{};
    ~Api() {
        if (module)
            FreeLibrary(module);
    }
    template <class T> void symbol(T &target, const char *name) {
        target = reinterpret_cast<T>(GetProcAddress(module, name));
        if (!target)
            throw std::runtime_error("Npcap 运行库不完整");
    }
    void load() {
        if (module)
            return;
        wchar_t system[MAX_PATH]{};
        if (!GetSystemDirectoryW(system, MAX_PATH))
            throw std::runtime_error("无法定位系统目录");
        auto path = std::filesystem::path(system) / L"Npcap" / L"wpcap.dll";
        if (!std::filesystem::exists(path))
            throw std::runtime_error("Npcap 未安装");
        module = LoadLibraryExW(path.c_str(), nullptr,
                                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module)
            throw std::runtime_error("Npcap 不可用");
        try {
            symbol(findAll, "pcap_findalldevs");
            symbol(freeAll, "pcap_freealldevs");
            symbol(openLive, "pcap_open_live");
            symbol(close, "pcap_close");
            symbol(datalink, "pcap_datalink");
            symbol(setNonblock, "pcap_setnonblock");
            symbol(next, "pcap_next_ex");
            symbol(stats, "pcap_stats");
            symbol(getError, "pcap_geterr");
            symbol(compile, "pcap_compile");
            symbol(setFilter, "pcap_setfilter");
            symbol(freeCode, "pcap_freecode");
            symbol(lookupNet, "pcap_lookupnet");
            getEvent =
                reinterpret_cast<decltype(getEvent)>(GetProcAddress(module, "pcap_getevent"));
            setMinToCopy = reinterpret_cast<decltype(setMinToCopy)>(
                GetProcAddress(module, "pcap_setmintocopy"));
        } catch (...) {
            FreeLibrary(module);
            module = nullptr;
            throw;
        }
    }
#else
    void load() {
        throw std::runtime_error("实时抓包当前仅支持 Windows Npcap");
    }
#endif
};
CaptureEngine::CaptureEngine(QObject *parent, CaptureHooks hooks)
    : QObject(parent), api_(std::make_unique<Api>()), hooks_(std::move(hooks)) {}
CaptureEngine::~CaptureEngine() {
    stop();
}
std::vector<CaptureInterface> CaptureEngine::interfaces(QString &error) {
    std::vector<CaptureInterface> result;
    error.clear();
    try {
        if (hooks_.interfaces)
            return hooks_.interfaces(error);
        api_->load();
#ifdef _WIN32
        pcap_if_t *devices = nullptr;
        char err[PCAP_ERRBUF_SIZE]{};
        if (api_->findAll(&devices, err) != 0)
            throw std::runtime_error(err);
        struct Guard {
            Api *a;
            pcap_if_t *p;
            ~Guard() {
                a->freeAll(p);
            }
        } guard{api_.get(), devices};
        for (auto *d = devices; d; d = d->next) {
            QStringList addresses;
            for (auto *a = d->addresses; a; a = a->next)
                if (a->addr) {
                    if (a->addr->sa_family == AF_INET) {
                        auto *ip = reinterpret_cast<const sockaddr_in *>(a->addr);
                        const auto *b = reinterpret_cast<const unsigned char *>(&ip->sin_addr);
                        addresses << QString("%1.%2.%3.%4").arg(b[0]).arg(b[1]).arg(b[2]).arg(b[3]);
                    } else if (a->addr->sa_family == AF_INET6) {
                        auto *ip = reinterpret_cast<const sockaddr_in6 *>(a->addr);
                        std::array<std::uint8_t, 16> address{};
                        std::copy_n(reinterpret_cast<const std::uint8_t *>(&ip->sin6_addr), 16,
                                    address.begin());
                        addresses << QString::fromStdString(formatIpv6(address));
                    }
                }
            result.push_back({QString::fromLocal8Bit(d->name),
                              QString::fromLocal8Bit(d->description ? d->description : d->name),
                              addresses.join(", ")});
        }
#endif
    } catch (const std::exception &e) {
        error = QString::fromUtf8(e.what());
    }
    return result;
}
void CaptureEngine::reset() {
    stop();
    std::lock_guard lock(mutex_);
    queue_.clear();
    queuedBytes_ = 0;
    queuedEstimatedBytes_ = 0;
    peakQueuedEstimatedBytes_ = 0;
    waitWakeups_ = 0;
    waitStrategy_ = 0;
    received_ = 0;
    bytes_ = 0;
    queueDropped_ = 0;
    driverDropped_ = -1;
    untimedPackets_ = 0;
    untimedBytes_ = 0;
    enqueued_ = 0;
    peakQueuedPackets_ = 0;
    peakQueuedBytes_ = 0;
    ++generation_;
}
void CaptureEngine::enqueue(RawPacket raw, bool file, std::stop_token stop) {
    if (!file && hooks_.rawObserver)
        hooks_.rawObserver(raw);
    const auto n = raw.bytes.size();
    constexpr std::size_t estimatedLimit = 32 * 1024 * 1024;
    if (file) {
        std::unique_lock lock(mutex_);
        if (!queueSpace_.wait(lock, stop, [this] {
                return queue_.size() < 2048 && queuedBytes_ < 4 * 1024 * 1024 &&
                       queuedEstimatedBytes_ < 32 * 1024 * 1024;
            }))
            return;
    }
    {
        std::lock_guard lock(mutex_);
        if (!file) {
            ++received_;
            bytes_ += raw.originalLength;
            if (!raw.timestampValid) {
                ++untimedPackets_;
                untimedBytes_ += raw.originalLength;
            }
        }
        const std::size_t limit = file ? 32 * 1024 * 1024 : 8 * 1024 * 1024;
        if (!file && (queue_.size() >= 8192 || n > limit || queuedBytes_ > limit - n ||
                      queuedEstimatedBytes_ >= estimatedLimit)) {
            ++queueDropped_;
            return;
        }
    }
    auto packet = decodeSummary(std::move(raw));
    const auto footprint = packet.estimatedBytes;
    std::unique_lock lock(mutex_);
    if (file) {
        if (n > 32 * 1024 * 1024 || footprint > estimatedLimit)
            throw std::runtime_error("数据包超过队列预算");
        if (!queueSpace_.wait(lock, stop, [&] {
                return queue_.size() < 2048 && queuedBytes_ <= 32 * 1024 * 1024 - n &&
                       queuedEstimatedBytes_ <= estimatedLimit - footprint;
            }))
            return;
        ++received_;
        bytes_ += packet.raw.originalLength;
        if (!packet.raw.timestampValid) {
            ++untimedPackets_;
            untimedBytes_ += packet.raw.originalLength;
        }
    } else if (footprint > estimatedLimit || queuedEstimatedBytes_ > estimatedLimit - footprint) {
        ++queueDropped_;
        return;
    }
    queue_.push_back(std::move(packet));
    queuedBytes_ += n;
    queuedEstimatedBytes_ += footprint;
    ++enqueued_;
    peakQueuedPackets_ = std::max<std::uint64_t>(peakQueuedPackets_, queue_.size());
    peakQueuedBytes_ = std::max<std::uint64_t>(peakQueuedBytes_, queuedBytes_);
    peakQueuedEstimatedBytes_ =
        std::max<std::uint64_t>(peakQueuedEstimatedBytes_, queuedEstimatedBytes_);
}
void CaptureEngine::startLive(const QString &device, LiveCaptureOptions options) {
    start(device, false, {}, std::move(options));
}
void CaptureEngine::startFile(const QString &path, PreparedFile reader) {
    start(path, true, std::move(reader));
}
void CaptureEngine::start(const QString &target, bool file, PreparedFile reader,
                          LiveCaptureOptions options) {
    reset();
    running_ = true;
    try {
        worker_ = std::jthread([this, target, file, reader = std::move(reader),
                                options = std::move(options),
                                epoch = generation_](std::stop_token stop) {
            try {
                if (hooks_.run)
                    hooks_.run(
                        target, file, stop,
                        [this, file, stop](RawPacket raw) { enqueue(std::move(raw), file, stop); },
                        [this, epoch, stop](const QString &text) {
                            if (!stop.stop_requested())
                                emit opened(epoch, text);
                        },
                        options);
                else if (file)
                    runFile(target, epoch, stop, reader);
                else
                    runLive(target, epoch, stop, options);
            } catch (const std::exception &e) {
                emit failed(epoch, QString::fromUtf8(e.what()));
            }
            running_ = false;
            emit finished(epoch);
        });
    } catch (const std::exception &e) {
        running_ = false;
        emit failed(generation_, QString::fromUtf8(e.what()));
        emit finished(generation_);
    }
}
void CaptureEngine::runLive(const QString &device, quint64 epoch, std::stop_token stop,
                            const LiveCaptureOptions &options) {
    api_->load();
#ifdef _WIN32
    char err[PCAP_ERRBUF_SIZE]{};
    const auto name = device.toLocal8Bit();
    auto *handle = api_->openLive(name.constData(), 65535, 1, 50, err);
    if (!handle)
        throw std::runtime_error(std::string("无法打开接口: ") + err);
    struct Guard {
        Api *a;
        pcap_t *p;
        ~Guard() {
            a->close(p);
        }
    } guard{api_.get(), handle};
    const auto linkType = api_->datalink(handle);
    if (linkType != DLT_EN10MB && linkType != DLT_NULL)
        throw std::runtime_error("接口链路类型不支持");
    if (options.bpf.contains(QChar(0)))
        throw std::runtime_error("捕获过滤包含无效字符");
    if (!options.bpf.trimmed().isEmpty()) {
        bpf_u_int32 network{}, mask = PCAP_NETMASK_UNKNOWN;
        char lookupError[PCAP_ERRBUF_SIZE]{};
        if (api_->lookupNet(name.constData(), &network, &mask, lookupError) != 0)
            mask = PCAP_NETMASK_UNKNOWN;
        bpf_program program{};
        const auto expression = options.bpf.toUtf8();
        if (api_->compile(handle, &program, expression.constData(), 1, mask) != 0)
            throw std::runtime_error(std::string("捕获过滤无效: ") + api_->getError(handle));
        struct FilterGuard {
            Api *api;
            bpf_program *program;
            ~FilterGuard() {
                api->freeCode(program);
            }
        } filterGuard{api_.get(), &program};
        if (api_->setFilter(handle, &program) != 0)
            throw std::runtime_error(std::string("捕获过滤安装失败: ") + api_->getError(handle));
    }
    if (stop.stop_requested())
        return;
    if (api_->setNonblock(handle, 1, err) != 0)
        throw std::runtime_error(err);
    HANDLE stopped = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopped)
        throw std::runtime_error("停止事件创建失败");
    struct EventGuard {
        HANDLE value;
        ~EventGuard() {
            CloseHandle(value);
        }
    } stoppedGuard{stopped};
    std::stop_callback notifyStop(stop, [stopped] { SetEvent(stopped); });
    HANDLE dataEvent =
        api_->getEvent && !hooks_.disableDataEvent ? api_->getEvent(handle) : nullptr;
    if (dataEvent == INVALID_HANDLE_VALUE)
        dataEvent = nullptr;
    if (dataEvent && (!api_->setMinToCopy || api_->setMinToCopy(handle, 1) != 0))
        dataEvent = nullptr;
    waitStrategy_ = dataEvent ? 1 : 2;
    bool waitForData = false;
    emit opened(epoch, "捕获中");
    auto last = std::chrono::steady_clock::now();
    while (!stop.stop_requested()) {
        if (waitForData) {
            const HANDLE events[]{stopped, dataEvent};
            const auto result =
                WaitForMultipleObjects(dataEvent ? 2 : 1, events, FALSE, dataEvent ? 1000 : 20);
            ++waitWakeups_;
            if (result == WAIT_OBJECT_0 || stop.stop_requested())
                break;
            if (result == WAIT_FAILED) {
                dataEvent = nullptr;
                waitStrategy_ = 2;
                continue;
            }
        }
        pcap_pkthdr *h = nullptr;
        const u_char *data = nullptr;
        const int status = api_->next(handle, &h, &data);
        waitForData = status == 0;
        if (status == 1) {
            if (h->caplen > 65535 || h->caplen > h->len)
                throw std::runtime_error("驱动返回了异常数据包长度");
            RawPacket raw;
            raw.timestampNs =
                std::int64_t(h->ts.tv_sec) * 1000000000 + std::int64_t(h->ts.tv_usec) * 1000;
            raw.originalLength = h->len;
            raw.linkType = static_cast<std::uint32_t>(linkType);
            raw.bytes.assign(data, data + h->caplen);
            enqueue(std::move(raw), false, stop);
        } else if (status == -1)
            throw std::runtime_error(api_->getError(handle));
        else if (status == -2)
            break;

        if (std::chrono::steady_clock::now() - last >= std::chrono::seconds(1)) {
            pcap_stat s{};
            if (api_->stats(handle, &s) == 0)
                driverDropped_ = s.ps_drop;
            last = std::chrono::steady_clock::now();
        }
    }
    pcap_stat s{};
    if (api_->stats(handle, &s) == 0)
        driverDropped_ = s.ps_drop;
#else
    (void)device;
    (void)epoch;
    (void)stop;
    (void)options;
#endif
}
void CaptureEngine::runFile(const QString &path, quint64 epoch, std::stop_token stop,
                            PreparedFile reader) {
    if (!reader)
        reader = std::make_shared<PcapReader>(std::filesystem::path(path.toStdWString()));
    emit opened(epoch, "读取中");
    while (!stop.stop_requested()) {
        auto raw = reader->next();
        if (!raw)
            break;
        enqueue(std::move(*raw), true, stop);
    }
}
void CaptureEngine::requestStop() {
    if (worker_.joinable())
        worker_.request_stop();
}
void CaptureEngine::stop() {
    requestStop();
    if (worker_.joinable())
        worker_.join();
    running_ = false;
}
std::vector<Packet> CaptureEngine::takeBatch(std::size_t maxPackets) {
    std::vector<Packet> out;
    {
        std::lock_guard lock(mutex_);
        const auto count = std::min(maxPackets, queue_.size());
        out.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            queuedBytes_ -= queue_.front().raw.bytes.size();
            queuedEstimatedBytes_ -= queue_.front().estimatedBytes;
            out.push_back(std::move(queue_.front()));
            queue_.pop_front();
        }
    }
    queueSpace_.notify_one();
    return out;
}
CaptureCounters CaptureEngine::counters() const {
    std::lock_guard lock(mutex_);
    CaptureCounters c;
    c.received = received_;
    c.bytes = bytes_;
    c.queueDropped = queueDropped_;
    c.untimedPackets = untimedPackets_;
    c.untimedBytes = untimedBytes_;
    auto drop = driverDropped_.load();
    if (drop >= 0)
        c.driverDropped = static_cast<std::uint64_t>(drop);
    c.enqueued = enqueued_;
    c.queuedPackets = queue_.size();
    c.queuedBytes = queuedBytes_;
    c.peakQueuedPackets = peakQueuedPackets_;
    c.peakQueuedBytes = peakQueuedBytes_;
    c.queuedEstimatedBytes = queuedEstimatedBytes_;
    c.peakQueuedEstimatedBytes = peakQueuedEstimatedBytes_;
    c.waitWakeups = waitWakeups_;
    c.waitStrategy = waitStrategy_ == 1 ? "event" : (waitStrategy_ == 2 ? "timeout" : "source");
    return c;
}
} // namespace etherscope
