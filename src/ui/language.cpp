#include "ui/language.h"
#include <QAbstractButton>
#include <QAction>
#include <QComboBox>
#include <QCoreApplication>
#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPointer>
#include <QResource>
#include <QSignalBlocker>
#include <QStandardItemModel>
#include <QTabBar>
#include <QTreeWidget>
#include <QTranslator>
#include <QWidget>
#include <stdexcept>

static void initLanguageResources() {
    Q_INIT_RESOURCE(localization);
}
namespace etherscope::i18n {
namespace {
struct Message {
    QString simplified, en, traditional;
};
const QHash<QString, Message> &messages() {
    static const auto catalog = [] {
        initLanguageResources();
        QFile file(":/i18n/messages.json");
        if (!file.open(QIODevice::ReadOnly))
            throw std::runtime_error("Translation catalog unavailable");
        const auto document = QJsonDocument::fromJson(file.readAll());
        if (!document.isArray())
            throw std::runtime_error("Invalid translation catalog");
        QHash<QString, Message> result;
        for (const auto &value : document.array()) {
            const auto row = value.toArray();
            if (row.size() != 3 || row[0].toString().isEmpty() || row[1].toString().isEmpty() ||
                row[2].toString().isEmpty())
                throw std::runtime_error("Invalid translation entry");
            result.insert(row[0].toString(),
                          {row[0].toString(), row[1].toString(), row[2].toString()});
        }
        for (const auto &value : document.array()) {
            const auto row = value.toArray();
            if (!result.contains(row[1].toString()))
                result.insert(row[1].toString(),
                              {row[0].toString(), row[1].toString(), row[2].toString()});
        }
        return result;
    }();
    return catalog;
}
bool han(QChar ch) {
    return ch.unicode() >= 0x4e00 && ch.unicode() <= 0x9fff;
}
bool translatable(const QString &source) {
    if (messages().contains(source))
        return true;
    for (const auto ch : source)
        if (han(ch))
            return true;
    return false;
}
class DialogTranslator final : public QTranslator {
  public:
    using QTranslator::QTranslator;
    bool isEmpty() const override {
        return false;
    }
    QString translate(const char *, const char *source, const char *, int) const override {
        if (i18n::language().current() == "en")
            return {};
        static const QHash<QString, QString> labels = {
            {"Open", "打开"},
            {"Save", "保存"},
            {"Cancel", "取消"},
            {"Close", "关闭"},
            {"OK", "确定"},
            {"Yes", "是"},
            {"No", "否"},
            {"File name:", "文件名:"},
            {"Files of type:", "文件类型:"},
            {"Look in:", "查找范围:"},
            {"Save in:", "保存位置:"},
            {"Name", "名称"},
            {"Size", "大小"},
            {"Type", "类型"},
            {"Date Modified", "修改时间"},
            {"Back", "后退"},
            {"Forward", "前进"},
            {"Parent Directory", "上级目录"},
            {"Create New Folder", "新建文件夹"},
            {"List View", "列表"},
            {"Detail View", "详细信息"},
            {"Show hidden files", "显示隐藏文件"},
            {"New Folder", "新建文件夹"},
            {"Folder", "文件夹"},
            {"Directory:", "目录:"},
            {"Choose", "选择"},
            {"All Files (*)", "所有文件 (*)"},
            {"All files (*)", "所有文件 (*)"},
            {"%1 already exists.\nDo you want to replace it?", "%1 已存在。\n是否替换?"},
            {"%1\nFile not found.\nPlease verify the correct file name was given.",
             "%1\n未找到文件。\n请检查文件名。"},
            {"Show ", "显示 "},
            {"Read-only", "只读"},
            {"Rename", "重命名"},
            {"Delete", "删除"},
            {"Show Details", "显示详细信息"},
            {"Hide Details", "隐藏详细信息"},
            {"File", "文件"},
            {"Find Directory", "选择目录"},
            {"Recent Places", "最近位置"},
            {"Computer", "计算机"},
            {"My Computer", "我的计算机"}};
        const auto clean = QString::fromUtf8(source).remove('&');
        const auto found = labels.constFind(clean);
        return found == labels.cend() ? QString{} : text(*found);
    }
};
void property(QObject *object, const char *name) {
    const auto source = object->property(name).toString();
    if (!translatable(source))
        return;
    auto apply = [object, name, source] {
        if (!object->property("_dynamicLanguageBound").toBool())
            object->setProperty(name, text(source));
    };
    QObject::connect(&language(), &Language::changed, object, apply);
    apply();
}
} // namespace
Language::Language(QObject *parent) : QObject(parent) {
    messages();
}
Language &language() {
    static QPointer<Language> instance;
    if (!instance)
        instance = new Language(QCoreApplication::instance());
    return *instance;
}
QString normalize(QString code) {
    code = code.trimmed().replace('-', '_');
    if (code.compare("en", Qt::CaseInsensitive) == 0 || code.startsWith("en_", Qt::CaseInsensitive))
        return "en";
    if (code.compare("zh_CN", Qt::CaseInsensitive) == 0 ||
        code.compare("zh_SG", Qt::CaseInsensitive) == 0 ||
        code.startsWith("zh_Hans", Qt::CaseInsensitive))
        return "zh_CN";
    if (code.compare("zh_TW", Qt::CaseInsensitive) == 0 ||
        code.compare("zh_HK", Qt::CaseInsensitive) == 0 ||
        code.compare("zh_MO", Qt::CaseInsensitive) == 0 ||
        code.startsWith("zh_Hant", Qt::CaseInsensitive))
        return "zh_TW";
    return {};
}
QString systemLanguage() {
    const auto result = normalize(QLocale::system().name());
    return result.isEmpty() ? QString("en") : result;
}
bool Language::set(const QString &code) {
    const auto normalized = normalize(code);
    if (normalized.isEmpty())
        return false;
    static QPointer<DialogTranslator> dialogs;
    if (!dialogs) {
        dialogs = new DialogTranslator(this);
        QCoreApplication::installTranslator(dialogs);
    }
    {
        QWriteLocker lock(&lock_);
        if (current_ == normalized)
            return true;
        current_ = normalized;
    }
    QCoreApplication::removeTranslator(dialogs);
    QCoreApplication::installTranslator(dialogs);
    emit changed();
    return true;
}
QString text(const QString &source) {
    const auto code = language().current();
    const auto &catalog = messages();
    auto translation = [&](const Message &m) -> const QString & {
        return code == "en" ? m.en : (code == "zh_CN" ? m.simplified : m.traditional);
    };
    if (const auto found = catalog.constFind(source); found != catalog.cend())
        return translation(*found);
    if (code == "zh_CN" || !translatable(source))
        return source;
    QString output;
    output.reserve(source.size() * 2);
    for (qsizetype at = 0; at < source.size();) {
        if (!han(source[at])) {
            auto ch = source[at++];
            if (code == "en") {
                if (ch == QChar(0xff0c))
                    ch = ',';
                else if (ch == QChar(0xff1a))
                    ch = ':';
                else if (ch == QChar(0xff1b))
                    ch = ';';
                else if (ch == QChar(0xff08))
                    ch = '(';
                else if (ch == QChar(0xff09))
                    ch = ')';
                else if (ch == QChar(0x3002))
                    ch = '.';
            }
            output += ch;
            continue;
        }
        const auto begin = at;
        while (at < source.size() && han(source[at]))
            ++at;
        const auto phrase = source.mid(begin, at - begin);
        const auto found = catalog.constFind(phrase);
        if (found == catalog.cend()) {
            output += phrase;
            continue;
        }
        if (code == "en" && !output.isEmpty() && output.back().isLetterOrNumber())
            output += ' ';
        output += translation(*found);
        if (code == "en" && at < source.size() && source[at].isLetterOrNumber())
            output += ' ';
    }
    return output;
}
QString errorText(const QString &source) {
    const auto detail = source.indexOf(": ");
    return detail < 0 ? text(source) : text(source.left(detail)) + source.mid(detail);
}
void setLabel(QLabel *label, const QString &source, const QStringList &arguments) {
    auto apply = [label] {
        auto value = errorText(label->property("_languageSource").toString());
        for (const auto &argument : label->property("_languageArguments").toStringList())
            value = value.arg(argument);
        label->setText(value);
    };
    if (!label->property("_dynamicLanguageBound").toBool()) {
        label->setProperty("_dynamicLanguageBound", true);
        QObject::connect(&language(), &Language::changed, label, apply);
    }
    label->setProperty("_languageSource", source);
    label->setProperty("_languageArguments", arguments);
    apply();
}
void bind(QWidget *root) {
    auto objects = root->findChildren<QObject *>();
    objects.prepend(root);
    for (auto *object : objects) {
        if (object->property("_languageBound").toBool())
            continue;
        object->setProperty("_languageBound", true);
        if (qobject_cast<QLabel *>(object) || qobject_cast<QAbstractButton *>(object) ||
            qobject_cast<QAction *>(object))
            property(object, "text");
        if (qobject_cast<QLineEdit *>(object))
            property(object, "placeholderText");
        if (auto *widget = qobject_cast<QWidget *>(object)) {
            property(widget, "windowTitle");
            property(widget, "toolTip");
            property(widget, "accessibleName");
        }
        if (auto *action = qobject_cast<QAction *>(object))
            property(action, "toolTip");
        if (auto *combo = qobject_cast<QComboBox *>(object)) {
            QStringList labels;
            for (int i = 0; i < combo->count(); ++i)
                labels << combo->itemText(i);
            auto apply = [combo, labels] {
                QSignalBlocker block(combo);
                for (int i = 0; i < labels.size() && i < combo->count(); ++i)
                    combo->setItemText(i, text(labels[i]));
            };
            QObject::connect(&language(), &Language::changed, combo, apply);
            apply();
        }
        if (auto *tabs = qobject_cast<QTabBar *>(object)) {
            QStringList labels;
            for (int i = 0; i < tabs->count(); ++i)
                labels << tabs->tabText(i);
            auto apply = [tabs, labels] {
                for (int i = 0; i < labels.size() && i < tabs->count(); ++i)
                    tabs->setTabText(i, text(labels[i]));
            };
            QObject::connect(&language(), &Language::changed, tabs, apply);
            apply();
        }
        if (auto *tree = qobject_cast<QTreeWidget *>(object)) {
            QStringList labels;
            for (int i = 0; i < tree->columnCount(); ++i)
                labels << tree->headerItem()->text(i);
            auto apply = [tree, labels] {
                for (int i = 0; i < labels.size(); ++i)
                    tree->headerItem()->setText(i, text(labels[i]));
            };
            QObject::connect(&language(), &Language::changed, tree, apply);
            apply();
        }
        if (auto *model = qobject_cast<QStandardItemModel *>(object)) {
            QStringList labels;
            for (int i = 0; i < model->columnCount(); ++i)
                labels << model->headerData(i, Qt::Horizontal).toString();
            auto apply = [model, labels] {
                for (int i = 0; i < labels.size(); ++i)
                    model->setHeaderData(i, Qt::Horizontal, text(labels[i]));
            };
            QObject::connect(&language(), &Language::changed, model, apply);
            apply();
        }
    }
}
} // namespace etherscope::i18n
