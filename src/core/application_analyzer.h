#pragma once
#include "core/application.h"
#include "core/display_filter.h"
#include "core/tls.h"

namespace etherscope {
ApplicationResult analyzeDatagram(const Packet& packet);
ApplicationResult analyzeConversation(const TcpStreamRequest& request,const TlsKeyLog& keys,std::stop_token stop={});
std::size_t estimateApplicationBytes(const ApplicationResult& result);
std::map<std::uint64_t,ApplicationFacts> indexApplication(const ApplicationResult& result,std::span<const std::shared_ptr<const Packet>> packets);
}
