#pragma once
#include "core/application.h"

namespace etherscope {
enum class FilterTruth { False, True, Unknown };
struct ApplicationFacts {
    AnalysisStatus status{AnalysisStatus::Pending};
    std::map<std::string, std::vector<ApplicationValue>> values;
};
class DisplayExpression {
  public:
    struct Implementation;
    DisplayExpression(std::string source, std::shared_ptr<const Implementation> implementation,
                      bool application);
    FilterTruth evaluate(const Packet &packet, const ApplicationFacts *facts = nullptr) const;
    const std::string &source() const {
        return source_;
    }
    bool requiresApplications() const {
        return application_;
    }

  private:
    std::string source_;
    std::shared_ptr<const Implementation> implementation_;
    bool application_{};
};
struct DisplayFilterResult {
    std::shared_ptr<const DisplayExpression> value;
    std::string error;
    std::size_t position{};
};
DisplayFilterResult compileDisplayFilter(std::string_view source);
} // namespace etherscope
