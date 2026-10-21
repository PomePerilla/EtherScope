#pragma once
#include "core/application.h"
#include <QWidget>
#include <QTimer>
class QComboBox;
class QTreeWidget;
class QTreeWidgetItem;
class QPlainTextEdit;
class QLabel;
namespace etherscope {
class ApplicationView final : public QWidget {
    Q_OBJECT
  public:
    explicit ApplicationView(QWidget *parent = nullptr);
    ~ApplicationView() override;
    void setResults(std::vector<std::shared_ptr<const ApplicationResult>> results);
  signals:
    void locateRequested(quint64 packet);

  private:
    std::vector<std::shared_ptr<const ApplicationResult>> results_;
    std::vector<const ApplicationMessage *> messages_;
    const ApplicationMessage *selected_{};
    QTreeWidget *list_{}, *fields_{};
    QComboBox *sources_{}, *packets_{};
    QPlainTextEdit *bytes_{};
    QLabel *page_{}, *state_{};
    QTimer fillTimer_;
    std::size_t filled_{}, fieldFilled_{}, offset_{}, preferredMessage_{};
    void rebuild();
    void fill();
    void select();
    void page(std::size_t offset);
    void highlightField();
};
} // namespace etherscope
