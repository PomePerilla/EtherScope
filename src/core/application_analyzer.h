#pragma once
#include "core/application.h"
#include "core/display_filter.h"
#include "core/tls.h"

namespace etherscope {
class ConversationAnalysis {
  public:
    ConversationAnalysis();
    ~ConversationAnalysis();
    // request.packets contains only packets not previously supplied to this instance.
    ApplicationResult append(const TcpStreamRequest &request, const TlsKeyLog &keys,
                             std::stop_token stop = {});
    void prune(std::uint64_t firstPacket);
    bool keysChanged(const TlsKeyLog &previous, const TlsKeyLog &next) const;
    std::size_t estimatedBytes() const;
    std::uint64_t deliveredBytes() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
ApplicationResult analyzeDatagram(const Packet &packet);
ApplicationResult analyzeConversation(const TcpStreamRequest &request, const TlsKeyLog &keys,
                                      std::stop_token stop = {});
std::size_t estimateApplicationFacts(const std::map<std::uint64_t, ApplicationFacts> &facts);
std::size_t estimateApplicationFact(const ApplicationFacts &facts);
std::map<std::uint64_t, ApplicationFacts>
indexApplication(const ApplicationResult &result,
                 std::span<const std::shared_ptr<const Packet>> packets);
} // namespace etherscope
