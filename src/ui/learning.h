#pragma once
#include "core/application.h"
#include <QString>
namespace etherscope::learning {
QString fieldExplanation(const QString &key, const QString &value);
QString statusExplanation(AnalysisStatus status);
QString quoted(const QString &text);
QString fieldPredicate(const QString &key, const ApplicationValue &value);
} // namespace etherscope::learning
