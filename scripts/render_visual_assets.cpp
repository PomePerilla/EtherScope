#include "ui/icons.h"
#include "ui/style.h"
#include <QApplication>
#include <QBuffer>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFontDatabase>
#include <QImage>
#include <QPainter>
#include <iostream>

using namespace etherscope;
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    if (QGuiApplication::platformName() == "offscreen") {
        const auto fonts = qEnvironmentVariable("WINDIR") + "/Fonts/";
        QFontDatabase::addApplicationFont(fonts + "consola.ttf");
        QFontDatabase::addApplicationFont(fonts + "segoeui.ttf");
    }
    const QString output = app.arguments().value(1, "src/ui/icons");
    QDir().mkpath(output);
    const QList<int> sizes{16, 20, 24, 32, 48, 64, 128, 256};
    QList<QByteArray> frames;
    QImage sheet(800, 300, QImage::Format_ARGB32_Premultiplied);
    sheet.fill(QColor("#111315"));
    QPainter preview(&sheet);
    preview.setFont(style::dataFont());
    int x = 12;
    for (int size : sizes) {
        // Supersample the code-native paths; no source bitmap is resampled or edited.
        QImage large(size * 4, size * 4, QImage::Format_ARGB32_Premultiplied);
        large.fill(Qt::transparent);
        QPainter painter(&large);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.scale(size * 4 / 100., size * 4 / 100.);
        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor(style::primary));
        painter.drawRoundedRect(QRectF(2, 2, 96, 96), 20, 20);
        painter.translate(7, 6);
        painter.scale(.86, .86);
        icons::drawBrand(painter, QColor("#16181B"), size <= 24);
        painter.end();
        auto image = large.scaled(size, size, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
        if (!image.save(output + QString("/app-%1.png").arg(size)))
            return 1;
        QByteArray png;
        QBuffer buffer(&png);
        buffer.open(QIODevice::WriteOnly);
        image.save(&buffer, "PNG");
        frames.append(png);
        preview.drawImage(x, 20, image);
        preview.setPen(QColor("#E8EAED"));
        preview.drawText(x, size + 42, QString::number(size));
        x += size + 18;
    }
    preview.end();
    if (!sheet.save(output + "/brand-sizes.png"))
        return 2;
    QByteArray ico;
    QDataStream data(&ico, QIODevice::WriteOnly);
    data.setByteOrder(QDataStream::LittleEndian);
    data << quint16(0) << quint16(1) << quint16(sizes.size());
    quint32 offset = 6 + 16 * quint32(sizes.size());
    for (int i = 0; i < sizes.size(); ++i) {
        const auto dimension = quint8(sizes[i] == 256 ? 0 : sizes[i]);
        data << dimension << dimension << quint8(0) << quint8(0) << quint16(1) << quint16(32)
             << quint32(frames[i].size()) << offset;
        offset += quint32(frames[i].size());
    }
    for (const auto &frame : frames)
        data.writeRawData(frame.constData(), frame.size());
    QFile file(output + "/etherscope.ico");
    if (!file.open(QIODevice::WriteOnly) || file.write(ico) != ico.size())
        return 3;
    const QString geometry =
        R"(<path fill-rule="evenodd" d="M65 12C43 2 15 17 10 42C4 64 18 87 41 91C52 94 63 91 70 87Q74 84 71 81L64 75Q62 73 59 73H40C30 73 24 68 22 62H49C60 62 65 55 65 48C65 40 59 35 50 35H22C24 27 31 23 40 23H62Q65 23 67 20L69 17Q71 14 65 12ZM27 44H49A5 5 0 0 1 49 54H27A5 5 0 0 1 27 44Z"/><g fill="none" stroke="currentColor" stroke-linecap="round"><path stroke-width="8.5" d="M71 34Q86 50 71 66"/><path stroke-width="10" d="M82 22Q106 50 82 78"/></g>)";
    for (const auto &variant : {QString("light"), QString("dark"), QString("navy")}) {
        const QString color =
            variant == "dark" ? style::primary : (variant == "navy" ? "#111827" : "#16181B");
        QFile svg(output + "/brand-on-" + variant + ".svg");
        if (!svg.open(QIODevice::WriteOnly))
            return 4;
        svg.write(("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\" fill=\"" +
                   color + "\" color=\"" + color + "\">" + geometry + "</svg>\n")
                      .toUtf8());
        QImage image(512, 512, QImage::Format_ARGB32_Premultiplied);
        image.fill(Qt::transparent);
        QPainter painter(&image);
        painter.scale(5.12, 5.12);
        icons::drawBrand(painter, QColor(color));
        painter.end();
        if (!image.save(output + "/brand-on-" + variant + ".png"))
            return 5;
    }
    QImage catalog(820, 200, QImage::Format_ARGB32_Premultiplied);
    catalog.fill(QColor("#17191C"));
    QPalette palette;
    palette.setColor(QPalette::Base, QColor("#17191C"));
    app.setPalette(palette);
    QPainter painter(&catalog);
    painter.setFont(style::dataFont());
    const QStringList names{"Brand",  "Start",      "Stop",   "Open",        "Save",  "Refresh",
                            "Filter", "Expression", "TCP",    "Application", "Key",   "Record",
                            "Chart",  "Diagnostic", "Locate", "More",        "Theme", "Language",
                            "Close",  "Warning",    "Error"};
    for (int i = 0; i < names.size(); ++i) {
        const int left = (i % 11) * 74 + 6, top = (i / 11) * 90 + 12;
        icons::icon(static_cast<icons::Id>(i), false, 32)
            .paint(&painter, QRect(left + 18, top, 32, 32));
        painter.setPen(QColor("#E8EAED"));
        painter.drawText(QRect(left, top + 40, 74, 30), Qt::AlignCenter, names[i]);
    }
    painter.end();
    if (!catalog.save(output + "/functional-icons.png"))
        return 6;
    std::cout << "Generated brand variants, 8 ICO frames, and icon catalog\n";
}
