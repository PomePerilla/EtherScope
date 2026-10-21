#include "core/application.h"
#include "core/bytes.h"
#include <algorithm>
#include <set>

namespace etherscope {
void appendApplicationMessage(ApplicationResult &result, ApplicationMessage message) {
    std::size_t nodes = message.fields.size();
    for (const auto &existing : result.messages)
        nodes += existing.fields.size();
    if (nodes > maxPacketFields)
        throw std::length_error("Application field limit reached");
    result.messages.push_back(std::move(message));
    result.estimatedBytes = estimateApplicationBytes(result);
    if (result.estimatedBytes > applicationResultLimit) {
        result.messages.pop_back();
        throw std::length_error("Application result limit reached");
    }
}
std::string applicationText(const ApplicationValue &value) {
    if (const auto *text = std::get_if<std::string>(&value))
        return *text;
    if (const auto *boolean = std::get_if<bool>(&value))
        return *boolean ? "true" : "false";
    return std::to_string(std::get<std::uint64_t>(value));
}
std::vector<SourceSpan> messageSources(const ApplicationInput &input, std::size_t offset,
                                       std::size_t length) {
    std::vector<SourceSpan> result;
    for (const auto &source : input.sources) {
        if (input.source == DataSource::Decrypted) {
            const auto logical = source.bufferLength ? source.bufferLength : source.length;
            if (offset < source.bufferOffset + logical && source.bufferOffset < offset + length)
                result.push_back(source);
            continue;
        }
        const auto start = std::max(offset, source.bufferOffset),
                   end = std::min(offset + length, source.bufferOffset + source.length);
        if (start < end)
            result.push_back({source.packetId, source.rawOffset + start - source.bufferOffset,
                              end - start, start});
    }
    return result;
}
namespace {
class Dns {
  public:
    Dns(const ApplicationInput &input, std::size_t offset, std::size_t length)
        : input_(input), base_(offset), bytes_(ByteView(*input.bytes).slice(offset, length)),
          view_(bytes_) {
        message_.protocol = "DNS";
        message_.direction = input.direction;
        message_.source = input.source;
        message_.bytes = input.bytes;
        message_.offset = offset;
        message_.length = length;
        message_.sources = messageSources(input, offset, length);
    }
    ApplicationMessage run() {
        add("Transaction ID", "dns.id", view_.integer(0, 2), 0, 2);
        const auto flags = view_.integer(2, 2);
        add("Response", "dns.flags.response", bool(flags & 0x8000), 2, 2);
        add("Response code", "dns.flags.rcode", flags & 15, 2, 2);
        add("Flags", "dns.flags", flags, 2, 2);
        const auto questions = view_.integer(4, 2);
        std::uint64_t records = 0;
        for (std::size_t i = 6; i < 12; i += 2)
            records += view_.integer(i, 2);
        if (questions + records > maxPacketFields / 2)
            throw std::length_error("Application field limit reached");
        std::size_t cursor = 12;
        for (std::uint64_t i = 0; i < questions; ++i) {
            const auto start = cursor;
            const auto qname = name(cursor);
            add("Name", "dns.qry.name", qname, start, cursor - start);
            add("Type", "dns.qry.type", view_.integer(cursor, 2), cursor, 2);
            add("Class", "dns.qry.class", view_.integer(cursor + 2, 2), cursor + 2, 2);
            cursor += 4;
            if (message_.summary.empty())
                message_.summary = qname;
        }
        for (std::uint64_t i = 0; i < records; ++i)
            record(cursor);
        if (cursor != bytes_.size())
            throw std::runtime_error("DNS trailing data");
        message_.summary = (flags & 0x8000 ? "Response " : "Query ") + message_.summary;
        return std::move(message_);
    }

  private:
    const ApplicationInput &input_;
    std::size_t base_{};
    std::span<const std::uint8_t> bytes_;
    ByteView view_;
    ApplicationMessage message_;
    void add(std::string name, std::string key, ApplicationValue value, std::size_t offset,
             std::size_t length) {
        if (message_.fields.size() >= maxPacketFields)
            throw std::length_error("Application field limit reached");
        message_.fields.push_back(
            {std::move(name), std::move(key), std::move(value), base_ + offset, length});
    }
    std::string name(std::size_t &cursor) const {
        std::string result;
        auto at = cursor;
        std::size_t expanded = 1;
        bool jumped = false;
        std::set<std::size_t> visited;
        for (unsigned hops = 0; hops < 128; ++hops) {
            if (!visited.insert(at).second)
                throw std::runtime_error("DNS compression loop");
            const auto length = view_.integer(at, 1);
            if ((length & 0xc0) == 0xc0) {
                const auto pointer = ((length & 63) << 8) | view_.integer(at + 1, 1);
                if (pointer >= at)
                    throw std::runtime_error("Invalid DNS compression pointer");
                if (!jumped)
                    cursor = at + 2;
                jumped = true;
                at = static_cast<std::size_t>(pointer);
                continue;
            }
            if (length & 0xc0)
                throw std::runtime_error("Invalid DNS label");
            ++at;
            if (!length) {
                if (!jumped)
                    cursor = at;
                return result.empty() ? "." : result;
            }
            const auto label = view_.slice(at, static_cast<std::size_t>(length));
            expanded += 1 + static_cast<std::size_t>(length);
            if (expanded > 255)
                throw std::runtime_error("DNS name exceeds limit");
            if (!result.empty())
                result += '.';
            for (auto ch : label) {
                if (ch >= 33 && ch <= 126 && ch != '.' && ch != '\\')
                    result += char(ch);
                else {
                    const char digits[] = "0123456789abcdef";
                    result += "\\x";
                    result += digits[ch >> 4];
                    result += digits[ch & 15];
                }
            }
            if (result.size() > 1024)
                throw std::runtime_error("DNS name exceeds limit");
            at += static_cast<std::size_t>(length);
            if (!jumped)
                cursor = at;
        }
        throw std::runtime_error("DNS compression limit reached");
    }
    void record(std::size_t &cursor) {
        auto start = cursor;
        auto owner = name(cursor);
        add("Name", "dns.resp.name", std::move(owner), start, cursor - start);
        const auto type = view_.integer(cursor, 2);
        add("Type", "dns.resp.type", type, cursor, 2);
        add("Class", "dns.resp.class", view_.integer(cursor + 2, 2), cursor + 2, 2);
        add("TTL", "dns.resp.ttl", view_.integer(cursor + 4, 4), cursor + 4, 4);
        const auto length = static_cast<std::size_t>(view_.integer(cursor + 8, 2));
        cursor += 10;
        view_.slice(cursor, length);
        const auto end = cursor + length;
        if (type == 1 || type == 28) {
            if (length != (type == 1 ? 4u : 16u))
                throw std::runtime_error("Invalid DNS address length");
            std::string value;
            if (type == 1) {
                std::array<std::uint8_t, 4> a{};
                std::copy_n(bytes_.begin() + cursor, 4, a.begin());
                value = formatIp(a);
            } else {
                std::array<std::uint8_t, 16> a{};
                std::copy_n(bytes_.begin() + cursor, 16, a.begin());
                value = formatIpv6(a);
            }
            add("Address", type == 1 ? "dns.a" : "dns.aaaa", std::move(value), cursor, length);
            cursor = end;
        } else if (type == 2 || type == 5 || type == 12 || type == 15 || type == 33 || type == 6) {
            if (type == 15) {
                add("Preference", "dns.mx.preference", view_.integer(cursor, 2), cursor, 2);
                cursor += 2;
            }
            if (type == 33) {
                for (const auto key : {"dns.srv.priority", "dns.srv.weight", "dns.srv.port"}) {
                    add(key, key, view_.integer(cursor, 2), cursor, 2);
                    cursor += 2;
                }
            }
            start = cursor;
            auto value = name(cursor);
            add("Target",
                type == 5 ? "dns.cname"
                          : (type == 2 ? "dns.ns"
                                       : (type == 12 ? "dns.ptr"
                                                     : (type == 15 ? "dns.mx" : "dns.target"))),
                std::move(value), start, cursor - start);
            if (type == 6) {
                start = cursor;
                value = name(cursor);
                add("Mailbox", "dns.soa.mailbox", std::move(value), start, cursor - start);
                for (const auto key : {"dns.soa.serial", "dns.soa.refresh", "dns.soa.retry",
                                       "dns.soa.expire", "dns.soa.minimum"}) {
                    add(key, key, view_.integer(cursor, 4), cursor, 4);
                    cursor += 4;
                }
            }
        } else if (type == 16) {
            while (cursor < end) {
                const auto n = static_cast<std::size_t>(view_.integer(cursor++, 1));
                if (n > end - cursor)
                    throw std::runtime_error("Invalid DNS TXT length");
                const auto text = view_.slice(cursor, n);
                add("Text", "dns.txt",
                    std::string(reinterpret_cast<const char *>(text.data()), text.size()), cursor,
                    n);
                cursor += n;
            }
        } else if (type == 41) {
            while (cursor < end) {
                const auto code = view_.integer(cursor, 2), n = view_.integer(cursor + 2, 2);
                add("Option", "dns.opt.code", code, cursor, 2);
                cursor += 4;
                if (cursor > end || n > end - cursor)
                    throw std::runtime_error("Invalid DNS option length");
                cursor += static_cast<std::size_t>(n);
            }
        } else {
            add("Data", "", std::string("Raw"), cursor, length);
            cursor = end;
        }
        if (cursor != end)
            throw std::runtime_error("Invalid DNS record length");
    }
};
} // namespace
ApplicationResult decodeDns(const ApplicationInput &input, std::size_t offset, std::size_t length) {
    ApplicationResult result;
    try {
        if (!input.bytes)
            throw std::runtime_error("DNS data is missing");
        if (!length)
            length = input.bytes->size() - std::min(offset, input.bytes->size());
        appendApplicationMessage(result, Dns(input, offset, length).run());
    } catch (const std::length_error &e) {
        result.status = AnalysisStatus::Limited;
        result.error = e.what();
    } catch (const std::exception &e) {
        result.status = AnalysisStatus::Incomplete;
        result.error = e.what();
    }
    return result;
}
} // namespace etherscope
