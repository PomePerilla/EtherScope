#pragma once
#include "core/application.h"
#include <span>

namespace etherscope {
class TlsKeyLog {
public:
    using Random=std::array<std::uint8_t,32>;
    using Secrets=std::map<std::string,std::vector<std::uint8_t>>;
    ~TlsKeyLog();
    bool append(std::string_view lines);
    const std::vector<std::uint8_t>* find(const Random& random,std::string_view label) const;
    std::uint64_t revision() const {return revision_;}
private:
    std::map<Random,Secrets> entries_;
    std::uint64_t revision_{};
};
struct TlsResult {
    ApplicationResult analysis;
    std::array<ApplicationInput,2> plaintext;
    std::string alpn;
    bool decrypted{};
};
TlsResult decodeTls(const std::array<ApplicationInput,2>& input,const TlsKeyLog& keys,std::stop_token stop={});
namespace tls {
using Bytes=std::vector<std::uint8_t>;
struct Cipher {const char* name;const char* hash;std::size_t keyLength{},ivLength{};bool tls13{},chacha{};};
std::optional<Cipher> cipher(std::uint16_t suite,bool tls13);
Bytes expandLabel(std::span<const std::uint8_t> secret,std::string_view hash,std::string_view label,std::size_t size);
Bytes prf(std::span<const std::uint8_t> secret,std::string_view hash,std::span<const std::uint8_t> seed,std::size_t size);
std::optional<Bytes> decrypt(const Cipher& cipher,std::span<const std::uint8_t> key,std::span<const std::uint8_t> iv,
    std::span<const std::uint8_t> aad,std::span<const std::uint8_t> ciphertext,std::span<const std::uint8_t> tag);
}
}
