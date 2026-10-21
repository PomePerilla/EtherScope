#include "capture/export.h"
#include "capture/file_buffer.h"
#include "core/pcap_file.h"
#include <QSaveFile>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <ostream>
#include <streambuf>

namespace etherscope {
ExportEngine::ExportEngine(QObject *parent, ExportWriter writer)
    : QObject(parent), writer_(std::move(writer)) {}
ExportEngine::~ExportEngine() {
    if (worker_.joinable())
        worker_.join();
}
bool ExportEngine::start(const QString &path, PacketSnapshot snapshot, CaptureFormat format) {
    if (running_ || snapshot.empty() || path.isEmpty())
        return false;
    if (worker_.joinable())
        worker_.join();
    const auto job = ++generation_;
    running_ = true;
    std::size_t footprint = 0;
    for (const auto &packet : snapshot)
        if (packet)
            footprint +=
                packet->estimatedBytes ? packet->estimatedBytes : estimatePacketBytes(*packet);
    referencedBytes_ = footprint;
    try {
        worker_ = std::jthread([this, job, path, format, snapshot = std::move(snapshot)]() mutable {
            QString error;
            bool success = false;
            const auto count = static_cast<quint64>(snapshot.size());
            try {
                quint64 total = 24;
                std::vector<const Packet *> packets;
                packets.reserve(snapshot.size());
                for (const auto &p : snapshot) {
                    packets.push_back(p.get());
                    if (p)
                        total += 16 + p->raw.bytes.size();
                }
                QSaveFile file(path);
                file.setDirectWriteFallback(false);
                if (!file.open(QIODevice::WriteOnly))
                    throw std::runtime_error("文件保存失败");
                auto last = std::chrono::steady_clock::now();
                emit progress(job, 0, total);
                FileBuffer buffer(file, writer_, [&](quint64 bytes) {
                    const auto now = std::chrono::steady_clock::now();
                    if (now - last >= std::chrono::milliseconds(100)) {
                        emit progress(job, bytes, total);
                        last = now;
                    }
                });
                std::ostream stream(&buffer);
                writeCapture(stream, packets, format);
                stream.flush();
                if (!stream || !file.commit())
                    throw std::runtime_error("文件保存失败");
                success = true;
            } catch (const std::exception &e) {
                error = QString::fromUtf8(e.what());
            }
            // Release references to evicted cache records before publishing completion.
            snapshot.clear();
            referencedBytes_ = 0;
            running_ = false;
            emit finished(job, success, path, count, error);
        });
    } catch (const std::exception &) {
        referencedBytes_ = 0;
        running_ = false;
        return false;
    }
    return true;
}
} // namespace etherscope
