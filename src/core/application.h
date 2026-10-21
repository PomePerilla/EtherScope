#pragma once
#include "core/tcp_stream.h"
#include <map>
#include <variant>

namespace etherscope {
using ApplicationValue=std::variant<std::uint64_t,bool,std::string>;
enum class AnalysisStatus { Pending,Complete,Incomplete,Limited,MissingKeys,Unsupported,AuthenticationFailed };
enum class DataSource { Original,Reassembled,Decrypted };
// Buffer offsets never refer to ciphertext when source is Decrypted.
struct SourceSpan {
    std::uint64_t packetId{};
    std::size_t rawOffset{},length{},bufferOffset{};
    std::size_t bufferLength{};
};
struct ApplicationField {
    std::string name,key;
    ApplicationValue value;
    std::size_t offset{},length{};
};
struct ApplicationMessage {
    std::string protocol,summary;
    unsigned direction{};
    std::uint32_t streamId{};
    DataSource source{DataSource::Original};
    AnalysisStatus status{AnalysisStatus::Complete};
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
    std::size_t offset{},length{};
    std::vector<SourceSpan> sources;
    std::vector<ApplicationField> fields;
};
struct ApplicationResult {
    std::vector<ApplicationMessage> messages;
    AnalysisStatus status{AnalysisStatus::Complete};
    std::string error;
    std::size_t estimatedBytes{};
};
struct ApplicationInput {
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
    std::vector<SourceSpan> sources;
    unsigned direction{};
    DataSource source{DataSource::Reassembled};
    bool startKnown{},endKnown{},incomplete{};
};
inline constexpr std::size_t applicationBudget=64*1024*1024,applicationHeaderLimit=64*1024,applicationHeaderCount=256;
std::string applicationText(const ApplicationValue& value);
std::vector<SourceSpan> messageSources(const ApplicationInput& input,std::size_t offset,std::size_t length);
ApplicationResult decodeDns(const ApplicationInput& input,std::size_t offset=0,std::size_t length=0);
ApplicationResult decodeHttp1(const std::array<ApplicationInput,2>& input,std::stop_token stop={});
ApplicationResult decodeHttp2(const std::array<ApplicationInput,2>& input,std::stop_token stop={});
}
