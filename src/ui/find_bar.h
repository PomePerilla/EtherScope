#pragma once
#include <QWidget>
#include <QTimer>
#include <functional>
#include <memory>
#include <cstdint>
#include <vector>
class QLineEdit;
class QComboBox;
class QCheckBox;
class QLabel;
class QPushButton;
class QPlainTextEdit;
namespace etherscope {
void highlightFindBytes(QPlainTextEdit *view, std::size_t page, std::size_t size,
                        std::size_t offset, std::size_t length);
struct FindDocument {
    QString key, text;
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
};
struct FindSource {
    int count{};
    std::function<FindDocument(int)> read;
    std::function<bool()> valid;
};
struct FindTarget {
    QString name;
    QWidget *focus{};
    bool bytes{};
    std::function<FindSource()> capture;
    std::function<bool(const QString &, std::size_t, std::size_t)> locate;
};
// Search owns one bounded snapshot; only stable keys are retained in matches.
class FindBar final : public QWidget {
    Q_OBJECT
  public:
    explicit FindBar(QWidget *parent);
    void addTarget(FindTarget target);
    void openFor(QWidget *focus);
    void invalidate();
    void markChanged();
    void message(const QString &text);
    bool searching() const {
        return timer_.isActive();
    }

  protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

  private:
    struct Match {
        QString key;
        std::size_t offset{}, length{};
    };
    std::vector<FindTarget> targets_;
    std::vector<Match> matches_;
    FindSource source_;
    FindDocument document_;
    QTimer timer_;
    QLineEdit *input_{};
    QComboBox *scope_{}, *mode_{};
    QCheckBox *case_{};
    QLabel *status_{};
    QPushButton *previous_{}, *next_{};
    QByteArray needle_;
    QString query_;
    int row_{}, current_{-1};
    std::size_t byte_{};
    bool documentReady_{}, stale_{}, limited_{};
    void start();
    void scan();
    void move(int direction);
    void updateStatus();
};
} // namespace etherscope
