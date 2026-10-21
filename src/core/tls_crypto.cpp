#include "core/tls.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace etherscope {
namespace {
std::vector<std::uint8_t> unhex(std::string_view value) {
    if (value.size() % 2 || value.size() > 128)
        throw std::runtime_error("Invalid TLS key log value");
    std::vector<std::uint8_t> result;
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const int a = digit(value[i]), b = digit(value[i + 1]);
        if (a < 0 || b < 0)
            throw std::runtime_error("Invalid TLS key log value");
        result.push_back(static_cast<std::uint8_t>((a << 4) | b));
    }
    return result;
}
} // namespace
TlsKeyLog::~TlsKeyLog() {
    for (auto &[random, secrets] : entries_) {
        (void)random;
        for (auto &[label, value] : secrets) {
            (void)label;
            OPENSSL_cleanse(value.data(), value.size());
        }
    }
}
bool TlsKeyLog::append(std::string_view lines) {
    if (lines.size() > 8 * 1024 * 1024)
        throw std::length_error("TLS key log exceeds limit");
    // Parse into a temporary transaction so an invalid file cannot replace active keys.
    std::map<Random, Secrets> additions;
    std::istringstream input{std::string(lines)};
    std::string line;
    while (std::getline(input, line)) {
        if (line.size() > 512)
            throw std::runtime_error("TLS key log line exceeds limit");
        const auto first = line.find_first_not_of(" \t\r");
        if (first == std::string::npos || line[first] == '#')
            continue;
        std::istringstream row(line);
        std::string label, randomText, secretText, extra;
        if (!(row >> label >> randomText >> secretText) || (row >> extra))
            throw std::runtime_error("Invalid TLS key log line");
        if (label != "CLIENT_RANDOM" && label != "CLIENT_HANDSHAKE_TRAFFIC_SECRET" &&
            label != "SERVER_HANDSHAKE_TRAFFIC_SECRET" && label != "CLIENT_TRAFFIC_SECRET_0" &&
            label != "SERVER_TRAFFIC_SECRET_0")
            continue;
        const auto raw = unhex(randomText);
        auto secret = unhex(secretText);
        if (raw.size() != 32 ||
            (label == "CLIENT_RANDOM" ? secret.size() != 48
                                      : (secret.size() != 32 && secret.size() != 48)))
            throw std::runtime_error("Invalid TLS secret length");
        Random random{};
        std::copy(raw.begin(), raw.end(), random.begin());
        const auto *old = find(random, label);
        if (old && *old != secret)
            throw std::runtime_error("Conflicting TLS secrets");
        auto &group = additions[random];
        if (group.contains(label) && group[label] != secret)
            throw std::runtime_error("Conflicting TLS secrets");
        group[label] = std::move(secret);
    }
    std::size_t count = entries_.size();
    for (const auto &[random, secrets] : additions) {
        (void)secrets;
        if (!entries_.contains(random))
            ++count;
    }
    if (count > 8192)
        throw std::length_error("TLS secret limit reached");
    bool changed = false;
    for (auto &[random, secrets] : additions)
        for (auto &[label, secret] : secrets)
            if (!find(random, label)) {
                entries_[random][label] = std::move(secret);
                changed = true;
            }
    if (changed)
        ++revision_;
    return changed;
}
const std::vector<std::uint8_t> *TlsKeyLog::find(const Random &random,
                                                 std::string_view label) const {
    const auto group = entries_.find(random);
    if (group == entries_.end())
        return nullptr;
    const auto item = group->second.find(std::string(label));
    return item == group->second.end() ? nullptr : &item->second;
}
namespace tls {
namespace {
Bytes hmac(std::span<const std::uint8_t> key, std::string_view hash,
           std::span<const std::uint8_t> value) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr);
    std::array<std::uint8_t, 64> bytes{};
    std::size_t size = 0;
    const std::string algorithm(hash);
    if (!EVP_Q_mac(nullptr, "HMAC", nullptr, algorithm.c_str(), nullptr, key.data(), key.size(),
                   value.data(), value.size(), bytes.data(), bytes.size(), &size))
        throw std::runtime_error("TLS key derivation failed");
    return {bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(size)};
}
} // namespace
std::optional<Cipher> cipher(std::uint16_t suite, bool tls13) {
    if (tls13) {
        if (suite == 0x1301)
            return Cipher{"AES-128-GCM", "SHA256", 16, 12, true, false};
        if (suite == 0x1302)
            return Cipher{"AES-256-GCM", "SHA384", 32, 12, true, false};
        if (suite == 0x1303)
            return Cipher{"CHACHA20-POLY1305", "SHA256", 32, 12, true, true};
        return {};
    }
    switch (suite) {
    case 0x009c:
    case 0x009e:
    case 0xc02b:
    case 0xc02f:
        return Cipher{"AES-128-GCM", "SHA256", 16, 4, false, false};
    case 0x009d:
    case 0x009f:
    case 0xc02c:
    case 0xc030:
        return Cipher{"AES-256-GCM", "SHA384", 32, 4, false, false};
    case 0xcca8:
    case 0xcca9:
    case 0xccaa:
        return Cipher{"CHACHA20-POLY1305", "SHA256", 32, 12, false, true};
    default:
        return {};
    }
}
Bytes expandLabel(std::span<const std::uint8_t> secret, std::string_view hash,
                  std::string_view label, std::size_t size) {
    if (size > 256 || label.size() > 249)
        throw std::runtime_error("Invalid TLS key derivation length");
    Bytes info{static_cast<std::uint8_t>(size >> 8), static_cast<std::uint8_t>(size),
               static_cast<std::uint8_t>(label.size() + 6)};
    const std::string full = "tls13 " + std::string(label);
    info.insert(info.end(), full.begin(), full.end());
    info.push_back(0);
    Bytes output, previous;
    for (unsigned counter = 1; output.size() < size; ++counter) {
        auto message = previous;
        message.insert(message.end(), info.begin(), info.end());
        message.push_back(static_cast<std::uint8_t>(counter));
        previous = hmac(secret, hash, message);
        output.insert(output.end(), previous.begin(), previous.end());
    }
    output.resize(size);
    return output;
}
Bytes prf(std::span<const std::uint8_t> secret, std::string_view hash,
          std::span<const std::uint8_t> seed, std::size_t size) {
    if (size > 256)
        throw std::runtime_error("Invalid TLS key derivation length");
    Bytes output;
    auto a = hmac(secret, hash, seed);
    while (output.size() < size) {
        auto data = a;
        data.insert(data.end(), seed.begin(), seed.end());
        const auto block = hmac(secret, hash, data);
        output.insert(output.end(), block.begin(), block.end());
        a = hmac(secret, hash, a);
    }
    output.resize(size);
    return output;
}
std::optional<Bytes> decrypt(const Cipher &cipher, std::span<const std::uint8_t> key,
                             std::span<const std::uint8_t> iv, std::span<const std::uint8_t> aad,
                             std::span<const std::uint8_t> ciphertext,
                             std::span<const std::uint8_t> tag) {
    if (key.size() != cipher.keyLength || tag.size() != 16 || iv.size() != 12 ||
        ciphertext.size() > streamDirectionLimit || aad.size() > 32)
        return {};
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr);
    const auto fetched = std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>(
        EVP_CIPHER_fetch(nullptr, cipher.name, nullptr), EVP_CIPHER_free);
    auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!fetched || !context)
        throw std::runtime_error("TLS cipher initialization failed");
    Bytes result(ciphertext.size() + 16);
    int count = 0, size = 0;
    if (EVP_DecryptInit_ex(context.get(), fetched.get(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &count, aad.data(),
                          static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(context.get(), result.data(), &count, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
        return {};
    size = count;
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG, 16,
                            const_cast<std::uint8_t *>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(context.get(), result.data() + size, &count) != 1) {
        OPENSSL_cleanse(result.data(), result.size());
        return {};
    }
    result.resize(static_cast<std::size_t>(size + count));
    return result;
}
} // namespace tls
} // namespace etherscope
