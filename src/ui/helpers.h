#pragma once
#include <QString>
#include <QDir>
#include <QStandardPaths>
#include <string>
namespace etherscope {
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
