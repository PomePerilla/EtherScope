#include "core/tls.h"
#include "core/bytes.h"
#include "core/application_stream.h"
#include "core/application_buffer.h"
#include <algorithm>
#include <set>

namespace etherscope {
namespace {
using tls::Bytes;
struct Record {
    unsigned side;
    std::size_t offset, length;
    std::uint8_t type;
    std::uint16_t version;
    std::uint64_t packet;
};
struct Direction {
    Bytes secret, key, iv, handshakes;
    std::vector<SourceSpan> handshakeSources;
    std::size_t handshakeCursor{};
    std::uint64_t sequence{};
    bool encrypted{}, application{}, failed{}, handshakeDecrypted{};
    std::shared_ptr<Bytes> plaintext = std::make_shared<Bytes>();
};
struct Decoder {
    const std::array<ApplicationInput, 2> &input;
    const TlsKeyLog *keys;
    bool incremental{};
    std::uint64_t droppedThrough{}, retentionFloor{};
    std::array<std::uint64_t, 2> handshakeBase{}, plaintextBase{};
    TlsResult result;
    std::array<Direction, 2> directions;
    std::optional<unsigned> client;
    TlsKeyLog::Random clientRandom{}, serverRandom{};
    bool haveClient{}, haveServer{}, is13{};
    std::uint16_t suite{};
    std::optional<tls::Cipher> cipher;
    explicit Decoder(const std::array<ApplicationInput, 2> &data, const TlsKeyLog &log)
        : input(data), keys(&log) {}
    void status(AnalysisStatus state, const char *error) {
        if (result.analysis.status == AnalysisStatus::Complete ||
            state == AnalysisStatus::AuthenticationFailed || state == AnalysisStatus::Limited) {
            result.analysis.status = state;
            result.analysis.error = error;
        }
    }
    void add(ApplicationMessage &m, std::string name, std::string key, ApplicationValue value,
             std::size_t offset, std::size_t length) {
        if (m.fields.size() >= maxPacketFields)
            throw std::length_error("Application field limit reached");
        m.fields.push_back({std::move(name), std::move(key), std::move(value), offset, length});
    }
    void extensions(ApplicationMessage &m, std::span<const std::uint8_t> bytes, std::size_t cursor,
                    bool server) {
        ByteView view(bytes);
        if (cursor == bytes.size())
            return;
        const auto size = static_cast<std::size_t>(view.integer(cursor, 2));
        cursor += 2;
        if (size != bytes.size() - cursor)
            throw std::runtime_error("Invalid TLS extensions length");
        std::set<std::uint64_t> seen;
        while (cursor < bytes.size()) {
            const auto kind = view.integer(cursor, 2),
                       n = static_cast<std::size_t>(view.integer(cursor + 2, 2));
            cursor += 4;
            const auto end = cursor + n;
            view.slice(cursor, n);
            if (!seen.insert(kind).second)
                throw std::runtime_error("Duplicate TLS extension");
            if (kind == 0 && !server) {
                const auto length = view.integer(cursor, 2);
                auto at = cursor + 2;
                if (length != end - at)
                    throw std::runtime_error("Invalid TLS server name list");
                while (at < end) {
                    const auto type = view.integer(at, 1),
                               count = static_cast<std::size_t>(view.integer(at + 1, 2));
                    at += 3;
                    if (at > end || count > end - at)
                        throw std::runtime_error("Invalid TLS server name");
                    if (type == 0)
                        add(m, "Server name", "tls.sni",
                            std::string(reinterpret_cast<const char *>(bytes.data() + at), count),
                            at, count);
                    at += count;
                }
            } else if (kind == 16) {
                const auto length = view.integer(cursor, 2);
                auto at = cursor + 2;
                if (length != end - at)
                    throw std::runtime_error("Invalid TLS ALPN list");
                while (at < end) {
                    const auto count = static_cast<std::size_t>(view.integer(at++, 1));
                    if (!count || at > end || count > end - at)
                        throw std::runtime_error("Invalid TLS ALPN protocol");
                    std::string value(reinterpret_cast<const char *>(bytes.data() + at), count);
                    add(m, "ALPN", "tls.alpn", value, at, count);
                    if (server)
                        result.alpn = value;
                    at += count;
                }
            } else if (kind == 43 && server) {
                if (n != 2)
                    throw std::runtime_error("Invalid TLS selected version");
                const auto version = view.integer(cursor, 2);
                add(m, "Version", "tls.version", version, cursor, 2);
                is13 = version == 0x0304;
            }
            cursor = end;
        }
    }
    void traffic(unsigned side, bool application) {
        auto &d = directions[side];
        if (!cipher || !client)
            return;
        const std::string label = std::string(side == *client ? "CLIENT_" : "SERVER_") +
                                  (application ? "TRAFFIC_SECRET_0" : "HANDSHAKE_TRAFFIC_SECRET");
        d.application = application;
        const auto *secret = keys->find(clientRandom, label);
        if (!secret) {
            status(AnalysisStatus::MissingKeys, "TLS keys are missing");
            if (!incremental)
                d.failed = true;
            return;
        }
        if (secret->size() != (std::string_view(cipher->hash) == "SHA384" ? 48u : 32u))
            throw std::runtime_error("TLS secret hash length differs");
        d.secret = *secret;
        d.key = tls::expandLabel(d.secret, cipher->hash, "key", cipher->keyLength);
        d.iv = tls::expandLabel(d.secret, cipher->hash, "iv", 12);
        d.sequence = 0;
        d.application = application;
    }
    void legacyKeys() {
        if (!cipher || !client)
            return;
        const auto *master = keys->find(clientRandom, "CLIENT_RANDOM");
        if (!master) {
            status(AnalysisStatus::MissingKeys, "TLS keys are missing");
            return;
        }
        const std::string label = "key expansion";
        Bytes seed(label.begin(), label.end());
        seed.insert(seed.end(), serverRandom.begin(), serverRandom.end());
        seed.insert(seed.end(), clientRandom.begin(), clientRandom.end());
        auto material =
            tls::prf(*master, cipher->hash, seed, 2 * (cipher->keyLength + cipher->ivLength));
        for (unsigned index = 0; index < 2; ++index) {
            auto &d = directions[index ? 1 - *client : *client];
            const auto key = material.begin() +
                             static_cast<std::ptrdiff_t>(index * cipher->keyLength),
                       iv =
                           material.begin() + static_cast<std::ptrdiff_t>(2 * cipher->keyLength +
                                                                          index * cipher->ivLength);
            d.key.assign(key, key + static_cast<std::ptrdiff_t>(cipher->keyLength));
            d.iv.assign(iv, iv + static_cast<std::ptrdiff_t>(cipher->ivLength));
        }
    }
    void hello(ApplicationMessage &m, unsigned side, std::uint8_t type) {
        const auto &bytes = *m.bytes;
        ByteView view(bytes);
        auto cursor = m.offset + 4;
        const auto end = m.offset + m.length;
        const auto version = view.integer(cursor, 2);
        add(m, "Version", "tls.legacy_version", version, cursor, 2);
        cursor += 2;
        const auto random = view.slice(cursor, 32);
        if (type == 1) {
            client = side;
            std::copy(random.begin(), random.end(), clientRandom.begin());
            haveClient = true;
        } else {
            std::copy(random.begin(), random.end(), serverRandom.begin());
            haveServer = true;
        }
        cursor += 32;
        const auto session = static_cast<std::size_t>(view.integer(cursor++, 1));
        if (session > 32)
            throw std::runtime_error("Invalid TLS session ID");
        view.slice(cursor, session);
        cursor += session;
        if (type == 1) {
            const auto count = static_cast<std::size_t>(view.integer(cursor, 2));
            cursor += 2;
            if (!count || count % 2)
                throw std::runtime_error("Invalid TLS cipher list");
            view.slice(cursor, count);
            cursor += count;
            const auto compression = static_cast<std::size_t>(view.integer(cursor++, 1));
            if (!compression)
                throw std::runtime_error("Invalid TLS compression list");
            view.slice(cursor, compression);
            cursor += compression;
        } else {
            suite = static_cast<std::uint16_t>(view.integer(cursor, 2));
            add(m, "Cipher suite", "tls.cipher", std::uint64_t(suite), cursor, 2);
            cursor += 2;
            if (view.integer(cursor++, 1) != 0)
                throw std::runtime_error("Unsupported TLS compression");
        }
        if (cursor > end)
            throw std::runtime_error("Invalid TLS hello length");
        // Extension offsets are relative to the shared handshake buffer.
        extensions(m, std::span(bytes).first(end), cursor, type == 2);
        if (type == 2 && haveClient) {
            if (!is13)
                add(m, "Version", "tls.version", version, m.offset + 4, 2);
            static constexpr std::array<std::uint8_t, 32> retry{
                0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
                0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
                0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
            if (serverRandom == retry) {
                haveServer = false;
                return;
            }
            if (!is13 && version != 0x0303) {
                status(AnalysisStatus::Unsupported, "Unsupported TLS version");
                return;
            }
            cipher = tls::cipher(suite, is13);
            if (!cipher) {
                status(AnalysisStatus::Unsupported, "Unsupported TLS cipher suite");
                return;
            }
            if (is13) {
                traffic(0, false);
                traffic(1, false);
            } else
                legacyKeys();
        }
    }
    void handshake(unsigned side, std::span<const std::uint8_t> payload,
                   const std::vector<SourceSpan> &sources, bool decrypted) {
        auto &d = directions[side];
        if (payload.size() > applicationHeaderLimit - d.handshakes.size())
            throw std::length_error("TLS handshake limit reached");
        const auto old = d.handshakes.size();
        if (!old)
            d.handshakeDecrypted = decrypted;
        d.handshakes.insert(d.handshakes.end(), payload.begin(), payload.end());
        for (auto source : sources) {
            source.bufferOffset = old;
            source.bufferLength = payload.size();
            d.handshakeSources.push_back(source);
        }
        while (d.handshakes.size() - d.handshakeCursor >= 4) {
            ByteView view(d.handshakes);
            const auto at = d.handshakeCursor;
            const auto type = static_cast<std::uint8_t>(view.integer(at, 1));
            const auto length = static_cast<std::size_t>(view.integer(at + 1, 3));
            if (length > applicationHeaderLimit - 4)
                throw std::length_error("TLS handshake limit reached");
            if (length > d.handshakes.size() - at - 4)
                break;
            if (result.analysis.messages.size() >= 1024 && !incremental)
                throw std::length_error("TLS message limit reached");
            ApplicationInput source;
            source.bytes = std::make_shared<const Bytes>(d.handshakes);
            source.sources = d.handshakeSources;
            source.source = DataSource::Decrypted;
            ApplicationMessage m;
            m.protocol = "TLS";
            m.summary = "Handshake " + std::to_string(type);
            m.direction = side;
            m.source = decrypted ? DataSource::Decrypted : DataSource::Reassembled;
            m.bytes = source.bytes;
            m.offset = at;
            m.length = length + 4;
            m.sources = messageSources(source, at, m.length);
            add(m, "Handshake type", "tls.handshake.type", std::uint64_t(type), at, 1);
            if (type == 1 && haveClient && haveServer && !is13) {
                status(AnalysisStatus::Unsupported, "TLS renegotiation is unsupported");
                d.failed = true;
                return;
            }
            if (type == 1 || type == 2)
                hello(m, side, type);
            else if (type == 8) {
                extensions(m, std::span(*m.bytes).first(at + 4 + length), at + 4, true);
            } else if (type == 20 && is13 && cipher) {
                traffic(side, true);
            } else if (type == 24 && is13 && cipher) {
                if (length != 1 || view.integer(at + 4, 1) > 1 || !d.application)
                    throw std::runtime_error("Invalid TLS KeyUpdate");
                d.secret = tls::expandLabel(d.secret, cipher->hash, "traffic upd", d.secret.size());
                d.key = tls::expandLabel(d.secret, cipher->hash, "key", cipher->keyLength);
                d.iv = tls::expandLabel(d.secret, cipher->hash, "iv", 12);
                d.sequence = 0;
            }
            if (incremental)
                detail::freezeMessage(m, handshakeBase[side]);
            if (incremental)
                detail::appendStreamMessage(result.analysis, std::move(m), droppedThrough);
            else
                appendApplicationMessage(result.analysis, std::move(m));
            d.handshakeCursor += length + 4;
        }
    }
    std::optional<Bytes> open(const Record &record, std::span<const std::uint8_t> payload) {
        auto &d = directions[record.side];
        if (!cipher || d.key.empty()) {
            status(haveServer ? AnalysisStatus::MissingKeys : AnalysisStatus::Incomplete,
                   "TLS decryption context is missing");
            return {};
        }
        if (d.sequence == UINT64_MAX)
            throw std::runtime_error("TLS sequence limit reached");
        Bytes iv = d.iv, aad;
        auto body = payload;
        if (is13) {
            for (unsigned i = 0; i < 8; ++i)
                iv[iv.size() - 1 - i] ^= static_cast<std::uint8_t>(d.sequence >> (i * 8));
            aad.assign(
                input[record.side].bytes->begin() + static_cast<std::ptrdiff_t>(record.offset),
                input[record.side].bytes->begin() + static_cast<std::ptrdiff_t>(record.offset + 5));
        } else {
            if (!cipher->chacha) {
                if (body.size() < 24)
                    return {};
                iv.insert(iv.end(), body.begin(), body.begin() + 8);
                body = body.subspan(8);
            } else
                for (unsigned i = 0; i < 8; ++i)
                    iv[iv.size() - 1 - i] ^= static_cast<std::uint8_t>(d.sequence >> (i * 8));
            if (body.size() < 16)
                return {};
            for (unsigned i = 0; i < 8; ++i)
                aad.push_back(static_cast<std::uint8_t>(d.sequence >> ((7 - i) * 8)));
            const auto length = body.size() - 16;
            aad.push_back(record.type);
            aad.push_back(static_cast<std::uint8_t>(record.version >> 8));
            aad.push_back(static_cast<std::uint8_t>(record.version));
            aad.push_back(static_cast<std::uint8_t>(length >> 8));
            aad.push_back(static_cast<std::uint8_t>(length));
        }
        if (body.size() < 16)
            return {};
        auto plaintext =
            tls::decrypt(*cipher, d.key, iv, aad, body.first(body.size() - 16), body.last(16));
        ++d.sequence;
        return plaintext;
    }
    void processRecord(const Record &record) {
        auto &d = directions[record.side];
        if (d.failed)
            return;
        const auto payload =
            std::span(*input[record.side].bytes).subspan(record.offset + 5, record.length);
        const auto sources = messageSources(input[record.side], record.offset, record.length + 5);
        if (record.type == 20) {
            if (payload.size() != 1 || payload[0] != 1)
                throw std::runtime_error("Invalid TLS ChangeCipherSpec");
            if (!is13) {
                d.encrypted = true;
                d.sequence = 0;
            }
            return;
        }
        std::uint8_t type = record.type;
        std::optional<Bytes> plaintext;
        const bool encrypted = (is13 && type == 23) || (!is13 && d.encrypted);
        if (encrypted) {
            plaintext = open(record, payload);
            if (!plaintext) {
                if (cipher && !d.key.empty())
                    status(AnalysisStatus::AuthenticationFailed, "TLS authentication failed");
                d.failed = true;
                return;
            }
            if (is13) {
                while (!plaintext->empty() && plaintext->back() == 0)
                    plaintext->pop_back();
                if (plaintext->empty())
                    throw std::runtime_error("Invalid TLS inner plaintext");
                type = plaintext->back();
                plaintext->pop_back();
                if (type != 21 && type != 22 && type != 23)
                    throw std::runtime_error("Invalid TLS inner content type");
            }
            result.decrypted = true;
        }
        const auto bytes = plaintext ? std::span<const std::uint8_t>(*plaintext) : payload;
        if (type == 22)
            handshake(record.side, bytes,
                      encrypted
                          ? sources
                          : messageSources(input[record.side], record.offset + 5, record.length),
                      encrypted);
        else if (type == 23 && encrypted) {
            if (bytes.size() > streamDirectionLimit - d.plaintext->size())
                throw std::length_error("TLS plaintext limit reached");
            const auto offset = d.plaintext->size();
            d.plaintext->insert(d.plaintext->end(), bytes.begin(), bytes.end());
            result.plaintext[record.side].startKnown = true;
            for (auto source : sources) {
                source.bufferOffset = offset;
                source.bufferLength = bytes.size();
                result.plaintext[record.side].sources.push_back(source);
            }
            ApplicationMessage m;
            m.protocol = "TLS";
            m.summary = "Application data";
            m.direction = record.side;
            m.source = DataSource::Decrypted;
            m.bytes = d.plaintext;
            m.offset = offset;
            m.length = bytes.size();
            m.sources = messageSources(result.plaintext[record.side], offset, bytes.size());
            add(m, "Decrypted", "tls.decrypted", true, offset, 0);
            if (incremental)
                detail::freezeMessage(m, plaintextBase[record.side]);
            if (incremental)
                detail::appendStreamMessage(result.analysis, std::move(m), droppedThrough);
            else
                appendApplicationMessage(result.analysis, std::move(m));
        } else if (type == 23) {
            status(AnalysisStatus::Unsupported, "TLS early data is unsupported");
        }
    }
    TlsResult run(std::stop_token stop) {
        std::vector<Record> records;
        for (unsigned side = 0; side < 2; ++side) {
            result.plaintext[side].bytes = directions[side].plaintext;
            result.plaintext[side].direction = side;
            result.plaintext[side].source = DataSource::Decrypted;
            result.plaintext[side].endKnown = input[side].endKnown;
            if (!input[side].bytes || input[side].bytes->empty())
                continue;
            if (!input[side].startKnown) {
                status(AnalysisStatus::Incomplete, "TLS connection prefix is missing");
                directions[side].failed = true;
                continue;
            }
            const auto &bytes = *input[side].bytes;
            ByteView view(bytes);
            std::size_t at = 0;
            while (at < bytes.size()) {
                if (records.size() >= 4096)
                    throw std::length_error("TLS record limit reached");
                if (bytes.size() - at < 5) {
                    status(AnalysisStatus::Incomplete, "Incomplete TLS record");
                    break;
                }
                const auto n = static_cast<std::size_t>(view.integer(at + 3, 2));
                if (n > 18432)
                    throw std::runtime_error("Invalid TLS record length");
                if (n > bytes.size() - at - 5) {
                    status(AnalysisStatus::Incomplete, "Incomplete TLS record");
                    break;
                }
                Record r{
                    side, at, n, bytes[at], static_cast<std::uint16_t>(view.integer(at + 1, 2)), 0};
                if (r.type < 20 || r.type > 24 || r.version < 0x0301 || r.version > 0x0303)
                    throw std::runtime_error("Invalid TLS record header");
                for (const auto &source : messageSources(input[side], at, n + 5))
                    r.packet = std::max(r.packet, source.packetId);
                records.push_back(r);
                at += n + 5;
            }
            if (input[side].incomplete)
                status(AnalysisStatus::Incomplete, "TLS stream is incomplete");
        }
        std::array<std::vector<const Record *>, 2> ordered;
        for (const auto &record : records)
            ordered[record.side].push_back(&record);
        std::array<std::size_t, 2> cursor{};
        for (std::size_t index = 0; index < records.size(); ++index) {
            unsigned side = cursor[0] == ordered[0].size() ? 1 : 0;
            if (cursor[1] < ordered[1].size() && cursor[0] < ordered[0].size()) {
                if (ordered[1][cursor[1]]->packet < ordered[0][cursor[0]]->packet)
                    side = 1;
                // Reassembly can complete earlier records after their peer's reply.
                // Keep each direction in stream order and establish the hello keys first.
                if (!haveClient)
                    for (unsigned candidate = 0; candidate < 2; ++candidate) {
                        const auto &next = *ordered[candidate][cursor[candidate]];
                        if (next.type == 22 && next.length &&
                            (*input[candidate].bytes)[next.offset + 5] == 1)
                            side = candidate;
                    }
                else if (!haveServer && client)
                    side = 1 - *client;
            }
            const auto &record = *ordered[side][cursor[side]++];
            if (stop.stop_requested())
                break;
            processRecord(record);
        }
        for (unsigned side = 0; side < 2; ++side) {
            const auto &d = directions[side];
            if (d.handshakeCursor != d.handshakes.size())
                status(AnalysisStatus::Incomplete, "Incomplete TLS handshake");
            result.plaintext[side].incomplete = input[side].incomplete || d.failed;
        }
        return std::move(result);
    }
};
} // namespace
TlsResult decodeTls(const std::array<ApplicationInput, 2> &input, const TlsKeyLog &keys,
                    std::stop_token stop) {
    Decoder decoder(input, keys);
    try {
        return decoder.run(stop);
    } catch (const std::length_error &e) {
        decoder.result.analysis.status = AnalysisStatus::Limited;
        decoder.result.analysis.error = e.what();
    } catch (const std::exception &e) {
        decoder.result.analysis.status = AnalysisStatus::Incomplete;
        decoder.result.analysis.error = e.what();
    }
    return std::move(decoder.result);
}
struct TlsStream::Impl {
    std::array<detail::ApplicationBuffer, 2> buffers;
    std::array<ApplicationInput, 2> input;
    std::array<std::size_t, 2> cursor{};
    std::unique_ptr<Decoder> decoder;
    std::optional<unsigned> helloSide;
    bool failed{};
    std::optional<Record> head(unsigned side) {
        const auto &data = *input[side].bytes;
        const auto at = cursor[side];
        if (!input[side].startKnown || !containsBytes(data.size(), at, 5))
            return {};
        ByteView view(data);
        const auto length = static_cast<std::size_t>(view.integer(at + 3, 2));
        if (length > 18432)
            throw std::runtime_error("Invalid TLS record length");
        if (!containsBytes(data.size(), at + 5, length))
            return {};
        Record record{
            side, at, length, data[at], static_cast<std::uint16_t>(view.integer(at + 1, 2)), 0};
        if (record.type < 20 || record.type > 24 || record.version < 0x0301 ||
            record.version > 0x0303)
            throw std::runtime_error("Invalid TLS record header");
        for (const auto &source : messageSources(input[side], at, length + 5))
            record.packet = std::max(record.packet, source.packetId);
        return record;
    }
};
TlsStream::TlsStream() : impl_(std::make_unique<Impl>()) {}
TlsStream::~TlsStream() = default;
TlsResult TlsStream::append(const std::array<ApplicationInput, 2> &incoming, const TlsKeyLog &keys,
                            std::stop_token stop) {
    auto &state = *impl_;
    if (!state.decoder) {
        state.decoder = std::make_unique<Decoder>(state.input, keys);
        state.decoder->incremental = true;
    }
    auto &decoder = *state.decoder;
    decoder.keys = &keys;
    if (!state.failed) {
        decoder.result.analysis.status = AnalysisStatus::Complete;
        decoder.result.analysis.error.clear();
    }
    decoder.result.decrypted = false;
    for (unsigned side = 0; side < 2; ++side) {
        decoder.plaintextBase[side] += decoder.directions[side].plaintext->size();
        decoder.directions[side].plaintext = std::make_shared<Bytes>();
        auto &target = decoder.result.plaintext[side];
        target = {};
        target.direction = side;
        target.source = DataSource::Decrypted;
        target.bytes = decoder.directions[side].plaintext;
    }
    try {
        if (!state.failed) {
            for (unsigned side = 0; side < 2; ++side) {
                state.buffers[side].append(incoming[side]);
                state.input[side] = state.buffers[side].data;
                decoder.result.plaintext[side].endKnown = state.input[side].endKnown;
            }
            if (decoder.haveServer && decoder.cipher && decoder.client) {
                if (decoder.is13) {
                    for (unsigned side = 0; side < 2; ++side)
                        if (decoder.directions[side].key.empty())
                            decoder.traffic(side, decoder.directions[side].application);
                } else if (decoder.directions[0].key.empty() || decoder.directions[1].key.empty())
                    decoder.legacyKeys();
            }
            for (unsigned count = 0; !stop.stop_requested(); ++count) {
                if (count >= 4096)
                    throw std::length_error("TLS record limit reached");
                std::array<std::optional<Record>, 2> heads{state.head(0), state.head(1)};
                if (!heads[0] && !heads[1])
                    break;
                std::optional<unsigned> side;
                for (unsigned candidate = 0; candidate < 2; ++candidate) {
                    if (!heads[candidate] || decoder.directions[candidate].failed)
                        continue;
                    const auto &record = *heads[candidate];
                    if (!decoder.haveClient) {
                        if (record.type != 22 || !record.length)
                            continue;
                        if (!state.helloSide &&
                            (*state.input[candidate].bytes)[record.offset + 5] == 1)
                            state.helloSide = candidate;
                        if (state.helloSide != candidate)
                            continue;
                    } else if (!decoder.haveServer && decoder.client &&
                               candidate == *decoder.client) {
                        if (record.type != 22)
                            continue;
                    }
                    const bool encrypted =
                        (decoder.is13 && record.type == 23) ||
                        (!decoder.is13 && decoder.directions[candidate].encrypted);
                    if (encrypted &&
                        (!decoder.cipher || decoder.directions[candidate].key.empty())) {
                        decoder.status(decoder.haveServer ? AnalysisStatus::MissingKeys
                                                          : AnalysisStatus::Incomplete,
                                       "TLS decryption context is missing");
                        continue;
                    }
                    if (!side || record.packet < heads[*side]->packet)
                        side = candidate;
                }
                if (!side)
                    break;
                const auto record = *heads[*side];
                decoder.processRecord(record);
                state.cursor[*side] += record.length + 5;
                if (decoder.result.analysis.status == AnalysisStatus::AuthenticationFailed ||
                    decoder.result.analysis.status == AnalysisStatus::Unsupported ||
                    decoder.result.analysis.status == AnalysisStatus::Limited)
                    state.failed = true;
                if (state.failed)
                    break;
            }
            for (unsigned side = 0; side < 2; ++side) {
                state.input[side] = {};
                state.buffers[side].consume(state.cursor[side]);
                state.cursor[side] = 0;
                auto &direction = decoder.directions[side];
                if (direction.handshakeCursor) {
                    const auto consumed = direction.handshakeCursor;
                    decoder.handshakeBase[side] += consumed;
                    direction.handshakes.erase(direction.handshakes.begin(),
                                               direction.handshakes.begin() +
                                                   static_cast<std::ptrdiff_t>(consumed));
                    for (auto source = direction.handshakeSources.begin();
                         source != direction.handshakeSources.end();) {
                        const auto length =
                            source->bufferLength ? source->bufferLength : source->length;
                        if (source->bufferOffset + length <= consumed) {
                            source = direction.handshakeSources.erase(source);
                        } else {
                            const auto removed = consumed > source->bufferOffset
                                                     ? consumed - source->bufferOffset
                                                     : 0;
                            if (!direction.handshakeDecrypted) {
                                source->rawOffset += removed;
                                source->length -= std::min(removed, source->length);
                            }
                            source->bufferLength = length - removed;
                            source->bufferOffset += removed;
                            source->bufferOffset -= consumed;
                            ++source;
                        }
                    }
                    direction.handshakeCursor = 0;
                }
                if ((state.buffers[side].size() ||
                     direction.handshakeCursor != direction.handshakes.size() ||
                     state.buffers[side].data.incomplete) &&
                    decoder.result.analysis.status == AnalysisStatus::Complete)
                    decoder.status(AnalysisStatus::Incomplete, "TLS stream is incomplete");
                decoder.result.plaintext[side].endKnown = state.buffers[side].data.endKnown &&
                                                          !state.buffers[side].size() &&
                                                          !direction.failed;
                decoder.result.plaintext[side].incomplete =
                    state.buffers[side].data.incomplete || direction.failed;
            }
        }
    } catch (const std::length_error &error) {
        state.failed = true;
        decoder.result.analysis.status = AnalysisStatus::Limited;
        decoder.result.analysis.error = error.what();
    } catch (const std::exception &error) {
        state.failed = true;
        decoder.result.analysis.status = AnalysisStatus::Incomplete;
        decoder.result.analysis.error = error.what();
    }
    auto snapshot = decoder.result;
    if (decoder.droppedThrough && decoder.droppedThrough >= decoder.retentionFloor) {
        snapshot.analysis.status = AnalysisStatus::Limited;
        snapshot.analysis.error = "Application result limit reached";
    }
    snapshot.analysis.estimatedBytes = estimateApplicationBytes(snapshot.analysis);
    return snapshot;
}
void TlsStream::prune(std::uint64_t first) {
    if (impl_->decoder) {
        impl_->decoder->retentionFloor = first;
        detail::pruneMessages(impl_->decoder->result.analysis, first);
    }
}
std::optional<TlsKeyLog::Random> TlsStream::clientRandom() const {
    if (!impl_->decoder || !impl_->decoder->haveClient)
        return {};
    return impl_->decoder->clientRandom;
}
std::size_t TlsStream::estimatedBytes() const {
    std::size_t bytes = sizeof(Impl);
    for (const auto &buffer : impl_->buffers)
        bytes += buffer.estimatedBytes();
    if (impl_->decoder) {
        bytes += sizeof(Decoder) + estimateApplicationBytes(impl_->decoder->result.analysis);
        for (const auto &direction : impl_->decoder->directions)
            bytes += direction.secret.capacity() + direction.key.capacity() +
                     direction.iv.capacity() + direction.handshakes.capacity() +
                     direction.handshakeSources.capacity() * sizeof(SourceSpan) +
                     direction.plaintext->capacity();
    }
    return bytes;
}
} // namespace etherscope
