#include "core/application.h"
#include "core/bytes.h"
#include <algorithm>
#include <charconv>
#include <deque>
#include <string_view>

namespace etherscope {
namespace {
std::string lower(std::string_view value) {
    std::string result(value);
    for (auto &c : result)
        if (c >= 'A' && c <= 'Z')
            c = char(c + ('a' - 'A'));
    return result;
}
std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
        value.remove_suffix(1);
    return value;
}
bool token(std::string_view value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               std::string_view("!#$%&'*+-.^_`|~").find(char(c)) != std::string_view::npos;
    });
}
std::uint64_t number(std::string_view value, int base = 10) {
    std::uint64_t n = 0;
    const auto [p, e] = std::from_chars(value.data(), value.data() + value.size(), n, base);
    if (e != std::errc{} || p != value.data() + value.size() || value.empty())
        throw std::runtime_error("Invalid HTTP length");
    return n;
}
struct Request {
    std::string method;
    std::uint64_t message{};
};
void field(ApplicationMessage &message, std::string name, std::string key, ApplicationValue value,
           std::size_t offset, std::size_t length) {
    if (message.fields.size() >= applicationHeaderCount + 8)
        throw std::length_error("HTTP header limit reached");
    message.fields.push_back({std::move(name), std::move(key), std::move(value), offset, length});
}
std::size_t chunks(std::string_view bytes, std::size_t at) {
    for (;;) {
        const auto end = bytes.find("\r\n", at);
        if (end == std::string_view::npos)
            throw std::runtime_error("Incomplete HTTP chunk");
        if (end - at > applicationHeaderLimit)
            throw std::length_error("HTTP chunk line exceeds limit");
        auto sizeText = bytes.substr(at, end - at);
        if (const auto extension = sizeText.find(';'); extension != std::string_view::npos)
            sizeText = sizeText.substr(0, extension);
        const auto size = number(trim(sizeText), 16);
        at = end + 2;
        if (!size) {
            const auto start = at;
            std::size_t count = 0;
            for (;;) {
                const auto trailer = bytes.find("\r\n", at);
                if (trailer == std::string_view::npos)
                    throw std::runtime_error("Incomplete HTTP trailers");
                if (trailer - start > applicationHeaderLimit || ++count > applicationHeaderCount)
                    throw std::length_error("HTTP trailer limit reached");
                if (trailer == at)
                    return at + 2;
                const auto colon = bytes.find(':', at);
                if (colon == std::string_view::npos || colon >= trailer ||
                    !token(bytes.substr(at, colon - at)))
                    throw std::runtime_error("Invalid HTTP trailer");
                at = trailer + 2;
            }
        }
        if (size > bytes.size() - at || bytes.size() - at - static_cast<std::size_t>(size) < 2)
            throw std::runtime_error("Incomplete HTTP chunk");
        at += static_cast<std::size_t>(size);
        if (bytes.substr(at, 2) != "\r\n")
            throw std::runtime_error("Invalid HTTP chunk delimiter");
        at += 2;
    }
}
void direction(const ApplicationInput &input, bool response, std::deque<Request> &requests,
               ApplicationResult &result, std::stop_token stop) {
    if (!input.bytes)
        return;
    const std::string_view bytes(reinterpret_cast<const char *>(input.bytes->data()),
                                 input.bytes->size());
    std::size_t at = 0;
    if (!input.startKnown && !bytes.empty()) {
        result.status = AnalysisStatus::Incomplete;
        return;
    }
    while (at < bytes.size() && !stop.stop_requested()) {
        if (result.messages.size() >= 1024)
            throw std::length_error("HTTP message limit reached");
        const auto headerEnd = bytes.find("\r\n\r\n", at);
        if (headerEnd == std::string_view::npos) {
            if (bytes.size() - at > applicationHeaderLimit)
                throw std::length_error("HTTP header limit reached");
            throw std::runtime_error("Incomplete HTTP headers");
        }
        if (headerEnd - at + 4 > applicationHeaderLimit)
            throw std::length_error("HTTP header limit reached");
        const auto lineEnd = bytes.find("\r\n", at);
        auto line = bytes.substr(at, lineEnd - at);
        ApplicationMessage m;
        m.protocol = "HTTP";
        m.direction = input.direction;
        m.source = input.source;
        m.bytes = input.bytes;
        m.offset = at;
        m.summary = std::string(line);
        std::uint64_t status = 0;
        std::string method;
        if (response) {
            if ((!line.starts_with("HTTP/1.0 ") && !line.starts_with("HTTP/1.1 ")) ||
                line.size() < 12 || (line.size() > 12 && line[12] != ' '))
                throw std::runtime_error("Invalid HTTP response line");
            status = number(line.substr(9, 3));
            if (status < 100 || status > 999)
                throw std::runtime_error("Invalid HTTP status");
            field(m, "Status", "http.response.code", status, at + 9, 3);
            if (!requests.empty()) {
                method = requests.front().method;
                field(m, "Request", "http.request.number", requests.front().message, at, 0);
            }
        } else {
            const auto space = line.find(' '), last = line.rfind(' ');
            if (space == std::string_view::npos || last == space || !token(line.substr(0, space)) ||
                (line.substr(last + 1) != "HTTP/1.0" && line.substr(last + 1) != "HTTP/1.1"))
                throw std::runtime_error("Invalid HTTP request line");
            method = std::string(line.substr(0, space));
            field(m, "Method", "http.request.method", method, at, space);
            field(m, "Target", "http.request.uri",
                  std::string(line.substr(space + 1, last - space - 1)), at + space + 1,
                  last - space - 1);
        }
        std::optional<std::uint64_t> contentLength;
        std::string encoding;
        auto cursor = lineEnd + 2;
        std::size_t headers = 0;
        while (cursor < headerEnd) {
            const auto end = bytes.find("\r\n", cursor), colon = bytes.find(':', cursor);
            if (end == std::string_view::npos || colon == std::string_view::npos || colon >= end ||
                !token(bytes.substr(cursor, colon - cursor)))
                throw std::runtime_error("Invalid HTTP header");
            if (++headers > applicationHeaderCount)
                throw std::length_error("HTTP header limit reached");
            const auto name = lower(bytes.substr(cursor, colon - cursor));
            const auto value = trim(bytes.substr(colon + 1, end - colon - 1));
            if (std::any_of(value.begin(), value.end(),
                            [](unsigned char c) { return (c < 32 && c != '\t') || c == 127; }))
                throw std::runtime_error("Invalid HTTP header value");
            field(m, name, name == "host" ? "http.host" : "http.header." + name, std::string(value),
                  colon + 1 + static_cast<std::size_t>(value.data() - (bytes.data() + colon + 1)),
                  value.size());
            if (name == "content-length") {
                const auto n = number(value);
                if (contentLength && *contentLength != n)
                    throw std::runtime_error("Conflicting HTTP content lengths");
                contentLength = n;
            }
            if (name == "transfer-encoding") {
                if (!encoding.empty())
                    encoding += ',';
                encoding += lower(value);
            }
            cursor = end + 2;
        }
        cursor = headerEnd + 4;
        const bool empty = response && ((status >= 100 && status < 200) || status == 204 ||
                                        status == 304 || method == "HEAD" ||
                                        (method == "CONNECT" && status >= 200 && status < 300));
        if (!encoding.empty() && contentLength)
            throw std::runtime_error("Conflicting HTTP body framing");
        try {
            if (!empty) {
                if (!encoding.empty()) {
                    const auto last = encoding.rfind(',');
                    if (trim(std::string_view(encoding).substr(
                            last == std::string::npos ? 0 : last + 1)) == "chunked")
                        cursor = chunks(bytes, cursor);
                    else if (response && input.endKnown)
                        cursor = bytes.size();
                    else
                        throw std::runtime_error("Unsupported HTTP transfer framing");
                } else if (contentLength) {
                    if (*contentLength > bytes.size() - cursor)
                        throw std::runtime_error("Incomplete HTTP body");
                    cursor += static_cast<std::size_t>(*contentLength);
                } else if (response) {
                    if (!input.endKnown)
                        throw std::runtime_error("HTTP body awaits connection close");
                    cursor = bytes.size();
                }
            }
        } catch (const std::exception &) {
            // Complete headers remain useful while a body is still arriving.
            m.length = bytes.size() - at;
            m.status = AnalysisStatus::Incomplete;
            m.sources = messageSources(input, at, m.length);
            appendApplicationMessage(result, std::move(m));
            if (!response)
                requests.push_back({method, result.messages.size()});
            throw;
        }
        m.length = cursor - at;
        m.sources = messageSources(input, at, m.length);
        appendApplicationMessage(result, std::move(m));
        at = cursor;
        if (!response)
            requests.push_back({method, result.messages.size()});
        else if ((status >= 200 || status == 101) && !requests.empty())
            requests.pop_front();
        if (response && (status == 101 || (method == "CONNECT" && status >= 200 && status < 300)))
            break;
    }
    if (input.incomplete)
        result.status = AnalysisStatus::Incomplete;
}
} // namespace
ApplicationResult decodeHttp1(const std::array<ApplicationInput, 2> &input, std::stop_token stop) {
    ApplicationResult result;
    std::deque<Request> requests;
    unsigned client = 0;
    for (unsigned side = 0; side < 2; ++side)
        if (input[side].bytes) {
            const std::string_view bytes(reinterpret_cast<const char *>(input[side].bytes->data()),
                                         input[side].bytes->size());
            if (bytes.starts_with("HTTP/1."))
                client = 1 - side;
        }
    for (unsigned index = 0; index < 2; ++index) {
        const auto side = index ? 1 - client : client;
        try {
            direction(input[side], index != 0, requests, result, stop);
        } catch (const std::length_error &e) {
            result.status = AnalysisStatus::Limited;
            result.error = e.what();
        } catch (const std::exception &e) {
            if (result.status != AnalysisStatus::Limited)
                result.status = AnalysisStatus::Incomplete;
            result.error = e.what();
        }
    }
    return result;
}
} // namespace etherscope
