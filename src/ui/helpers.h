#pragma once
#include <QString>
#include <QDir>
#include <QStandardPaths>
#include <cstdint>
#include <optional>
#include <string>
namespace etherscope {
struct DropCountDisplay {
    QString text;
    bool warning{};
};
inline DropCountDisplay dropCountDisplay(std::uint64_t queueDropped,
                                         std::optional<std::uint64_t> driverDropped,
                                         const QString &unknownText) {
    return {driverDropped ? QString::number(queueDropped + *driverDropped) : unknownText,
            queueDropped > 0 || (driverDropped && *driverDropped > 0)};
}
inline QString q(const std::string &s) {
    return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size()));
}
inline QString usableDirectory(const QString &directory) {
    if (!directory.isEmpty() && QDir(directory).exists())
        return directory;
    const auto documents = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    return QDir(documents).exists() ? documents : QDir::homePath();
}
} // namespace etherscope
