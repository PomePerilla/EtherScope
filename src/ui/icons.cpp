#include "ui/icons.h"
#include "ui/style.h"
#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCache>
#include <QPainterPath>
#include <QWidget>

namespace etherscope::icons {
void drawBrand(QPainter &p, const QColor &color, bool small) {
    p.setRenderHint(QPainter::Antialiasing);
    QPainterPath e;
    e.setFillRule(Qt::OddEvenFill);
    e.moveTo(65, 12);
    e.cubicTo(43, 2, 15, 17, 10, 42);
    e.cubicTo(4, 64, 18, 87, 41, 91);
    e.cubicTo(52, 94, 63, 91, 70, 87);
    e.quadTo(74, 84, 71, 81);
    e.lineTo(64, 75);
    e.quadTo(62, 73, 59, 73);
    e.lineTo(40, 73);
    e.cubicTo(30, 73, 24, 68, 22, 62);
    e.lineTo(49, 62);
    e.cubicTo(60, 62, 65, 55, 65, 48);
    e.cubicTo(65, 40, 59, 35, 50, 35);
    e.lineTo(22, 35);
    e.cubicTo(24, 27, 31, 23, 40, 23);
    e.lineTo(62, 23);
    e.quadTo(65, 23, 67, 20);
    e.lineTo(69, 17);
    e.quadTo(71, 14, 65, 12);
    e.closeSubpath();
    e.addRoundedRect(QRectF(22, small ? 43 : 44, 32, small ? 12 : 10), 6, 6);
    p.setPen(Qt::NoPen);
    p.setBrush(color);
    p.drawPath(e);
    p.setBrush(Qt::NoBrush);
    p.setPen(QPen(color, small ? 7.5 : 8.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    QPainterPath inner;
    inner.moveTo(71, 34);
    inner.quadTo(86, 50, 71, 66);
    p.drawPath(inner);
    p.setPen(QPen(color, small ? 9 : 10, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    QPainterPath outer;
    outer.moveTo(82, 22);
    outer.quadTo(106, 50, 82, 78);
    p.drawPath(outer);
}
namespace {
void draw(QPainter &p, Id id, const QColor &color) {
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(QPen(color, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    p.setBrush(Qt::NoBrush);
    auto path = [&](std::initializer_list<QPointF> points, bool close = false) {
        QPainterPath shape;
        auto it = points.begin();
        shape.moveTo(*it++);
        for (; it != points.end(); ++it)
            shape.lineTo(*it);
        if (close)
            shape.closeSubpath();
        p.drawPath(shape);
    };
    switch (id) {
    case Id::Brand:
        p.scale(.2, .2);
        drawBrand(p, color);
        break;
    case Id::Start:
        p.setBrush(color);
        path({{6, 4}, {15, 10}, {6, 16}}, true);
        break;
    case Id::Stop:
        p.setBrush(color);
        p.drawRoundedRect(QRectF(5, 5, 10, 10), 1.5, 1.5);
        break;
    case Id::Open:
        path({{3, 7}, {3, 5}, {8, 5}, {10, 7}, {16, 7}});
        path({{2, 8}, {18, 8}, {15, 16}, {4, 16}}, true);
        break;
    case Id::Save:
        path({{4, 3}, {14, 3}, {17, 6}, {17, 17}, {3, 17}, {3, 3}}, true);
        path({{7, 3}, {7, 8}, {13, 8}, {13, 3}});
        p.drawRect(QRectF(6, 12, 8, 5));
        break;
    case Id::Refresh:
        p.drawArc(QRectF(4, 4, 12, 12), 40 * 16, 290 * 16);
        path({{12, 3}, {17, 4}, {16, 9}});
        break;
    case Id::Filter:
        path({{3, 4}, {17, 4}, {12, 10}, {12, 15}, {8, 17}, {8, 10}}, true);
        break;
    case Id::Expression:
        path({{7, 5}, {3, 10}, {7, 15}});
        path({{13, 5}, {17, 10}, {13, 15}});
        path({{11, 4}, {9, 16}});
        break;
    case Id::Tcp:
        p.drawRoundedRect(QRectF(2, 4, 5, 5), 1, 1);
        p.drawRoundedRect(QRectF(13, 11, 5, 5), 1, 1);
        path({{7, 6.5}, {15.5, 6.5}, {15.5, 9}});
        path({{13, 13.5}, {4.5, 13.5}, {4.5, 11}});
        break;
    case Id::Application:
        path({{10, 3}, {18, 7}, {10, 11}, {2, 7}}, true);
        path({{3, 11}, {10, 15}, {17, 11}});
        path({{3, 15}, {10, 19}, {17, 15}});
        break;
    case Id::Key:
        p.drawEllipse(QRectF(3, 3, 7, 7));
        path({{9, 9}, {17, 17}, {17, 13}});
        path({{13, 13}, {15, 11}});
        break;
    case Id::Record:
        p.drawEllipse(QRectF(3, 3, 14, 14));
        p.setBrush(color);
        p.drawEllipse(QRectF(7, 7, 6, 6));
        break;
    case Id::Chart:
        path({{3, 3}, {3, 17}, {18, 17}});
        path({{6, 13}, {9, 9}, {12, 11}, {17, 5}});
        break;
    case Id::Diagnostic:
        path({{2, 10}, {6, 10}, {8, 4}, {12, 16}, {14, 10}, {18, 10}});
        break;
    case Id::Locate:
        p.drawEllipse(QRectF(5, 5, 10, 10));
        path({{10, 2}, {10, 6}});
        path({{10, 14}, {10, 18}});
        path({{2, 10}, {6, 10}});
        path({{14, 10}, {18, 10}});
        break;
    case Id::More:
        p.setBrush(color);
        for (int x : {4, 10, 16})
            p.drawEllipse(QPointF(x, 10), 1, 1);
        break;
    case Id::Theme:
        p.drawEllipse(QRectF(6, 6, 8, 8));
        for (int i = 0; i < 8; ++i) {
            p.save();
            p.translate(10, 10);
            p.rotate(i * 45);
            p.drawLine(QPointF(0, -7), QPointF(0, -8));
            p.restore();
        }
        break;
    case Id::Language:
        p.drawEllipse(QRectF(3, 3, 14, 14));
        p.drawEllipse(QRectF(7, 3, 6, 14));
        p.drawLine(QPointF(3, 10), QPointF(17, 10));
        break;
    case Id::Close:
        path({{6, 6}, {14, 14}});
        path({{14, 6}, {6, 14}});
        break;
    case Id::Warning:
        path({{10, 2}, {19, 17}, {1, 17}}, true);
        path({{10, 7}, {10, 11}});
        p.drawPoint(QPointF(10, 14));
        break;
    case Id::Info:
        p.drawEllipse(QRectF(3, 3, 14, 14));
        p.drawPoint(QPointF(10, 6));
        path({{10, 9}, {10, 14}});
        break;
    case Id::Check:
        path({{4, 10}, {8, 14}, {16, 6}});
        break;
    case Id::Float:
        path({{8, 4}, {4, 4}, {4, 16}, {16, 16}, {16, 12}});
        path({{10, 3}, {17, 3}, {17, 10}});
        path({{17, 3}, {9, 11}});
        break;
    case Id::Dock:
        p.drawRect(QRectF(3, 4, 14, 12));
        p.drawLine(QPointF(11, 4), QPointF(11, 16));
        break;
    case Id::Error:
        p.drawEllipse(QRectF(2, 2, 16, 16));
        path({{6.5, 6.5}, {13.5, 13.5}});
        path({{13.5, 6.5}, {6.5, 13.5}});
        break;
    }
}
void apply(QObject *object) {
    if (!object->property("visualIcon").isValid())
        return;
    const auto value = icon(static_cast<Id>(object->property("visualIcon").toInt()),
                            object->property("primaryIcon").toBool());
    if (auto *button = qobject_cast<QAbstractButton *>(object)) {
        button->setIcon(value);
        button->setIconSize(QSize(18, 18));
    } else if (auto *action = qobject_cast<QAction *>(object))
        action->setIcon(value);
}
} // namespace
QIcon icon(Id id, bool primary, int size) {
    const bool dark = qApp->palette().color(QPalette::Base).lightness() < 128;
    const auto c = style::colors(dark);
    const QString key = QString("%1/%2/%3/%4").arg(int(id)).arg(dark).arg(primary).arg(size);
    static QCache<QString, QIcon> cache(128);
    if (const auto *cached = cache.object(key))
        return *cached;
    QIcon result;
    for (auto mode : {QIcon::Normal, QIcon::Disabled, QIcon::Active, QIcon::Selected}) {
        QColor color(mode == QIcon::Disabled ? c.disabled : (primary ? "#16181B" : c.text));
        if (id == Id::Warning)
            color = style::warning(dark);
        if (id == Id::Error)
            color = c.error;
        for (qreal scale : {1., 1.5, 2., 3.}) {
            QPixmap pixmap(qRound(size * scale), qRound(size * scale));
            pixmap.fill(Qt::transparent);
            pixmap.setDevicePixelRatio(scale);
            QPainter painter(&pixmap);
            painter.scale(size / 20., size / 20.);
            draw(painter, id, color);
            painter.end();
            result.addPixmap(pixmap, mode);
        }
    }
    cache.insert(key, new QIcon(result));
    return result;
}
void bind(QAbstractButton *button, Id id, bool primary) {
    if (button->property("visualIcon").isValid() &&
        button->property("visualIcon").toInt() == int(id) &&
        button->property("primaryIcon").toBool() == primary)
        return;
    button->setProperty("visualIcon", int(id));
    button->setProperty("primaryIcon", primary);
    apply(button);
}
void bind(QAction *action, Id id) {
    if (action->property("visualIcon").isValid() &&
        action->property("visualIcon").toInt() == int(id))
        return;
    action->setProperty("visualIcon", int(id));
    apply(action);
}
void refresh(QWidget *root) {
    for (auto *object : root->findChildren<QObject *>())
        apply(object);
}
} // namespace etherscope::icons
