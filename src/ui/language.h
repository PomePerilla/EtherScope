#pragma once
#include <QObject>
#include <QString>
#include <QStringList>
#include <QReadWriteLock>
class QWidget;
class QLabel;

namespace etherscope::i18n {
class Language final:public QObject {
    Q_OBJECT
public:
    explicit Language(QObject* parent);
    QString current() const {QReadLocker lock(&lock_);return current_;}
    bool set(const QString& code);
signals:
    void changed();
private:
    QString current_{"zh_CN"};
    mutable QReadWriteLock lock_;
};
Language& language();
QString normalize(QString code);
QString systemLanguage();
QString text(const QString& source);
QString errorText(const QString& source);
void setLabel(QLabel* label,const QString& source,const QStringList& arguments={});
// Bind construction-time captions only. Packet data and user input are localized separately.
void bind(QWidget* root);
}
