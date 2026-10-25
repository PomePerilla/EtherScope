#pragma once
#include <QString>
#include <QDir>
#include <QStandardPaths>
#include <QTextEdit>
#include <QTextDocument>
#include <QAbstractTextDocumentLayout>
#include <QVBoxLayout>
#include <QScopedValueRollback>
#include <QResizeEvent>
#include <algorithm>
#include <string>
namespace etherscope {
class ExplanationText final : public QTextEdit {
  public:
    explicit ExplanationText(QWidget *parent) : QTextEdit(parent) {
        setReadOnly(true);
        setFrameShape(QFrame::NoFrame);
        setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
        setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        setProperty("explanation", true);
        document()->setDocumentMargin(8);
        setFixedHeight(36);
        connect(document()->documentLayout(), &QAbstractTextDocumentLayout::documentSizeChanged,
                this, [this] { fitText(); });
    }
    void fitText() {
        if (fitting_) return;
        const QScopedValueRollback<bool> fitting(fitting_, true);
        const auto height = std::clamp(int(document()->documentLayout()->documentSize().height()) + 2, 36, 96);
        if (height != this->height()) setFixedHeight(height);
    }
  protected:
    void resizeEvent(QResizeEvent *event) override {
        QTextEdit::resizeEvent(event);
        fitText();
    }
  private:
    bool fitting_{};
};
inline QWidget *explanationArea(QTextEdit *text, QWidget *parent) {
    auto *area = new QWidget(parent);
    area->setObjectName(text->objectName() + "Area");
    auto *layout = new QVBoxLayout(area);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(text);
    area->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    area->hide();
    return area;
}
inline void fitExplanation(QTextEdit *text) {
    static_cast<ExplanationText *>(text)->fitText();
}
inline void updateExplanation(QTextEdit *text, const QString &value) {
    if (text->toPlainText() == value) return;
    text->setPlainText(value);
    fitExplanation(text);
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
