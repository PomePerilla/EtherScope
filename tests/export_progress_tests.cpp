#include "capture/export.h"
#include "core/capture_file.h"
#include <QFile>
#include <QFileInfo>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <thread>

using namespace etherscope;

namespace {
PacketSnapshot pcapPackets(std::size_t count, std::size_t bytesPerPacket = 64) {
    PacketSnapshot result;
    result.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        auto packet = std::make_shared<Packet>();
        packet->raw.timestampNs = 1700000000000000000LL + static_cast<std::int64_t>(i) * 1000000;
        packet->raw.linkType = 1;
        packet->raw.originalLength = static_cast<std::uint32_t>(bytesPerPacket);
        packet->raw.bytes.resize(bytesPerPacket);
        for (std::size_t j = 0; j < bytesPerPacket; ++j)
            packet->raw.bytes[j] = static_cast<std::uint8_t>((i + j) & 0xff);
        result.push_back(std::move(packet));
    }
    return result;
}

PacketSnapshot pcapngPackets(std::size_t count) {
    auto firstInfo = std::make_shared<CaptureInterfaceInfo>();
    firstInfo->name = "sensor-alpha";
    firstInfo->description = "first interface metadata";
    firstInfo->snapLength = 128;
    firstInfo->fcsLength = 4;
    auto secondInfo = std::make_shared<CaptureInterfaceInfo>();
    secondInfo->name = "sensor-beta";
    secondInfo->description = "second interface with metadata";
    secondInfo->snapLength = 128;

    PacketSnapshot result;
    result.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        auto packet = std::make_shared<Packet>();
        auto &raw = packet->raw;
        raw.timestampNs = i == 1 ? 0 : 1700000000000000000LL +
                                          static_cast<std::int64_t>(i) * 1000000;
        raw.linkType = 1;
        raw.interfaceId = i == 1 ? 22 : 11;
        raw.timestampValid = i != 1;
        const auto length = i == 1 ? std::size_t(80) : std::size_t(60 + i % 8);
        raw.originalLength = static_cast<std::uint32_t>(length);
        raw.bytes.resize(length);
        for (std::size_t j = 0; j < length; ++j)
            raw.bytes[j] = static_cast<std::uint8_t>((i * 3 + j) & 0xff);
        raw.interfaceInfo = i == 1 ? secondInfo : firstInfo;
        result.push_back(std::move(packet));
    }
    return result;
}

ExportWriter slowWriter() {
    return [](QIODevice &device, const char *data, qint64 size) {
        std::this_thread::sleep_for(std::chrono::milliseconds(110));
        return device.write(data, size);
    };
}

void verifyProgress(QSignalSpy &progress, quint64 job, quint64 expectedRecords) {
    QVERIFY(progress.count() >= 3);
    quint64 previous = 0;
    quint64 observedTotal = 0;
    bool sawIntermediate = false;
    bool sawOverrun = false;
    bool monotone = true;
    bool oneTotal = true;
    bool first = true;
    for (const auto &event : progress) {
        QCOMPARE(event[0].toULongLong(), job);
        const auto current = event[1].toULongLong();
        const auto total = event[2].toULongLong();
        if (first) {
            observedTotal = total;
            first = false;
        } else if (total != observedTotal) {
            oneTotal = false;
        }
        sawOverrun = sawOverrun || current > total;
        monotone = monotone && current >= previous;
        if (current > 0 && current < total)
            sawIntermediate = true;
        previous = current;
    }
    QVERIFY2(!sawOverrun, "progress current exceeded the reported total");
    QVERIFY(monotone);
    QVERIFY(oneTotal);
    QCOMPARE(observedTotal, expectedRecords);
    QVERIFY(sawIntermediate);
    QCOMPARE(previous, expectedRecords);
}

void verifyFinished(QSignalSpy &finished, quint64 expectedCount) {
    QCOMPARE(finished.count(), 1);
    const auto event = finished.front();
    QVERIFY(event[1].toBool());
    QCOMPARE(event[3].toULongLong(), expectedCount);
}

} // namespace

class ExportProgressTests : public QObject {
    Q_OBJECT
  private slots:
    void pcapProgressTracksRecordsAndRoundTrips() {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto snapshot = pcapPackets(2000);
        const auto path = directory.filePath("slow.pcap");
        ExportEngine engine(nullptr, slowWriter());
        QSignalSpy progress(&engine, &ExportEngine::progress);
        QSignalSpy finished(&engine, &ExportEngine::finished);

        QVERIFY(engine.start(path, snapshot, CaptureFormat::Pcap));
        const auto job = engine.generation();
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 15000);
        verifyFinished(finished, snapshot.size());
        verifyProgress(progress, job, snapshot.size());
        QCOMPARE(QFileInfo(path).size(), qint64(24 + 2000 * (16 + 64)));

        CaptureReader reader(std::filesystem::path(path.toStdWString()));
        for (const auto &expected : snapshot) {
            const auto actual = reader.next();
            QVERIFY(actual.has_value());
            QCOMPARE(actual->bytes, expected->raw.bytes);
            QCOMPARE(actual->timestampNs, expected->raw.timestampNs);
        }
        QVERIFY(!reader.next().has_value());
    }

    void pcapngProgressTracksRecordsAndRoundTrips() {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto snapshot = pcapngPackets(2000);
        const auto path = directory.filePath("slow.pcapng");
        ExportEngine engine(nullptr, slowWriter());
        QSignalSpy progress(&engine, &ExportEngine::progress);
        QSignalSpy finished(&engine, &ExportEngine::finished);

        QVERIFY(engine.start(path, snapshot, CaptureFormat::Pcapng));
        const auto job = engine.generation();
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 15000);
        verifyFinished(finished, snapshot.size());
        verifyProgress(progress, job, snapshot.size());
        QVERIFY(QFileInfo(path).size() > 24 + 16 * 2000 + 64 * 2000);

        CaptureReader reader(std::filesystem::path(path.toStdWString()));
        for (std::size_t i = 0; i < snapshot.size(); ++i) {
            const auto actual = reader.next();
            QVERIFY(actual.has_value());
            QCOMPARE(actual->bytes, snapshot[i]->raw.bytes);
            QCOMPARE(actual->timestampValid, snapshot[i]->raw.timestampValid);
            QCOMPARE(actual->timestampNs, snapshot[i]->raw.timestampNs);
            QVERIFY(actual->interfaceInfo);
            if (i == 1) {
                QCOMPARE(actual->interfaceInfo->name, std::string("sensor-beta"));
                QCOMPARE(actual->interfaceInfo->description,
                         std::string("second interface with metadata"));
                QCOMPARE(actual->interfaceInfo->snapLength, std::uint32_t(128));
                QVERIFY(!actual->interfaceInfo->fcsLength.has_value());
            } else {
                QCOMPARE(actual->interfaceInfo->name, std::string("sensor-alpha"));
                QCOMPARE(actual->interfaceInfo->description,
                         std::string("first interface metadata"));
                QCOMPARE(actual->interfaceInfo->snapLength, std::uint32_t(128));
                QVERIFY(actual->interfaceInfo->fcsLength.has_value());
                QCOMPARE(*actual->interfaceInfo->fcsLength, std::uint8_t(4));
            }
            QCOMPARE(actual->interfaceId, i == 1 ? 0u : 1u);
        }
        QVERIFY(!reader.next().has_value());
    }

    void shortWritesStillProduceReadableFile() {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto snapshot = pcapPackets(3, 37);
        const auto path = directory.filePath("short-write.pcap");
        ExportEngine engine(nullptr, [](QIODevice &device, const char *data, qint64 size) {
            return device.write(data, std::min<qint64>(size, 7));
        });
        QSignalSpy finished(&engine, &ExportEngine::finished);

        QVERIFY(engine.start(path, snapshot, CaptureFormat::Pcap));
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 5000);
        verifyFinished(finished, snapshot.size());
        CaptureReader reader(std::filesystem::path(path.toStdWString()));
        for (const auto &expected : snapshot) {
            const auto actual = reader.next();
            QVERIFY(actual.has_value());
            QCOMPARE(actual->bytes, expected->raw.bytes);
        }
        QVERIFY(!reader.next().has_value());
    }

    void failedWritePreservesExistingFile() {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto path = directory.filePath("existing.pcap");
        QFile existing(path);
        QVERIFY(existing.open(QIODevice::WriteOnly));
        QCOMPARE(existing.write("keep-existing", 13), qint64(13));
        existing.close();
        const auto snapshot = pcapPackets(3, 37);
        auto calls = std::make_shared<std::atomic<int>>(0);
        ExportEngine engine(nullptr, [calls](QIODevice &device, const char *data, qint64 size) {
            if (calls->fetch_add(1) == 0)
                return device.write(data, std::min<qint64>(size, 8));
            return qint64(-1);
        });
        QSignalSpy progress(&engine, &ExportEngine::progress);
        QSignalSpy finished(&engine, &ExportEngine::finished);

        QVERIFY(engine.start(path, snapshot, CaptureFormat::Pcap));
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 5000);
        QVERIFY(!finished.front()[1].toBool());
        for (const auto &event : progress)
            QVERIFY(event[1].toULongLong() < event[2].toULongLong());
        QVERIFY(existing.open(QIODevice::ReadOnly));
        QCOMPARE(existing.readAll(), QByteArray("keep-existing"));
    }
};

QTEST_GUILESS_MAIN(ExportProgressTests)
#include "export_progress_tests.moc"
