#include "core/application.h"
#include "core/bytes.h"
#include "core/application_stream.h"
#include "core/application_buffer.h"
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

struct Http1Stream::Impl {
    enum class Body { Empty, Fixed, Chunked, Close };
    struct Pending {
        ApplicationMessage message;
        Body body{};
        std::size_t header{}, cursor{}, remaining{}, trailers{}, trailerStart{};
        unsigned stage{};
        std::uint64_t status{};
        std::string method;
    };
    std::array<detail::ApplicationBuffer, 2> buffers;
    std::array<std::optional<Pending>, 2> pending;
    std::array<bool, 2> done{};
    std::deque<Request> requests;
    std::optional<unsigned> client;
    std::uint64_t requestNumber{}, droppedThrough{}, retentionFloor{};
    ApplicationResult result;
    bool failed{};

    bool chunkEnd(Pending &p, std::string_view bytes) {
        for (;;) {
            if (p.stage == 1) {
                if (p.remaining > bytes.size() - p.cursor ||
                    bytes.size() - p.cursor - p.remaining < 2)
                    return false;
                p.cursor += p.remaining;
                if (bytes.substr(p.cursor, 2) != "\r\n")
                    throw std::runtime_error("Invalid HTTP chunk delimiter");
                p.cursor += 2;
                p.stage = 0;
            }
            const auto end = bytes.find("\r\n", p.cursor);
            if (end == std::string_view::npos) {
                if (bytes.size() - p.cursor > applicationHeaderLimit)
                    throw std::length_error("HTTP chunk line exceeds limit");
                return false;
            }
            if (end - p.cursor > applicationHeaderLimit)
                throw std::length_error("HTTP chunk line exceeds limit");
            const auto line = bytes.substr(p.cursor, end - p.cursor);
            if (p.stage == 2) {
                if (end - p.trailerStart > applicationHeaderLimit ||
                    ++p.trailers > applicationHeaderCount)
                    throw std::length_error("HTTP trailer limit reached");
                p.cursor = end + 2;
                if (line.empty())
                    return true;
                const auto colon = line.find(':');
                if (colon == std::string_view::npos || !token(line.substr(0, colon)))
                    throw std::runtime_error("Invalid HTTP trailer");
                continue;
            }
            p.remaining =
                static_cast<std::size_t>(number(trim(line.substr(0, line.find(';'))), 16));
            if (p.remaining > streamDirectionLimit)
                throw std::length_error("Application input limit reached");
            p.cursor = end + 2;
            p.stage = p.remaining ? 1 : 2;
            p.trailerStart = p.cursor;
        }
    }
    void process(unsigned side, std::stop_token stop) {
        auto &buffer = buffers[side];
        const bool response = side != *client;
        if (response && requests.empty() && !buffers[*client].data.endKnown)
            return;
        while (buffer.size() && !done[side] && !stop.stop_requested()) {
            const auto &input = buffer.data;
            const std::string_view bytes(reinterpret_cast<const char *>(input.bytes->data()),
                                         input.bytes->size());
            if (!input.startKnown)
                return;
            if (!pending[side]) {
                const auto end = bytes.find("\r\n\r\n");
                if (end == std::string_view::npos) {
                    if (bytes.size() > applicationHeaderLimit)
                        throw std::length_error("HTTP header limit reached");
                    return;
                }
                const auto length = end + 4;
                ApplicationInput header = input;
                header.bytes = std::make_shared<const std::vector<std::uint8_t>>(
                    input.bytes->begin(),
                    input.bytes->begin() + static_cast<std::ptrdiff_t>(length));
                header.sources = messageSources(input, 0, length);
                header.endKnown = header.incomplete = false;
                auto context = requests;
                ApplicationResult parsed;
                try {
                    direction(header, response, context, parsed, stop);
                } catch (const std::length_error &) {
                    throw;
                } catch (const std::exception &) {
                    if (parsed.messages.empty())
                        throw;
                }
                if (parsed.messages.empty())
                    return;
                Pending p;
                p.message = std::move(parsed.messages.front());
                p.header = p.cursor = length;
                std::optional<std::uint64_t> contentLength;
                std::string encoding;
                for (const auto &f : p.message.fields) {
                    if (f.key == "http.request.method")
                        p.method = std::get<std::string>(f.value);
                    else if (f.key == "http.response.code")
                        p.status = std::get<std::uint64_t>(f.value);
                    else if (f.key == "http.header.content-length")
                        contentLength = number(std::get<std::string>(f.value));
                    else if (f.key == "http.header.transfer-encoding") {
                        if (!encoding.empty())
                            encoding += ',';
                        encoding += lower(std::get<std::string>(f.value));
                    }
                }
                if (response && !requests.empty())
                    p.method = requests.front().method;
                const bool empty =
                    response && ((p.status >= 100 && p.status < 200) || p.status == 204 ||
                                 p.status == 304 || p.method == "HEAD" ||
                                 (p.method == "CONNECT" && p.status >= 200 && p.status < 300));
                if (empty)
                    p.body = Body::Empty;
                else if (!encoding.empty()) {
                    const auto last = encoding.rfind(',');
                    if (trim(std::string_view(encoding).substr(
                            last == std::string::npos ? 0 : last + 1)) == "chunked")
                        p.body = Body::Chunked;
                    else if (response)
                        p.body = Body::Close;
                    else
                        throw std::runtime_error("Unsupported HTTP transfer framing");
                } else if (contentLength) {
                    if (*contentLength > streamDirectionLimit - length)
                        throw std::length_error("Application input limit reached");
                    p.body = Body::Fixed;
                    p.remaining = static_cast<std::size_t>(*contentLength);
                } else
                    p.body = response ? Body::Close : Body::Empty;
                if (!response) {
                    if (requests.size() >= 1024)
                        throw std::length_error("HTTP message limit reached");
                    requests.push_back({p.method, ++requestNumber});
                }
                pending[side] = std::move(p);
            }
            auto &p = *pending[side];
            std::size_t end = p.header;
            if (p.body == Body::Fixed) {
                end += p.remaining;
                if (end > bytes.size())
                    return;
            } else if (p.body == Body::Chunked) {
                if (!chunkEnd(p, bytes))
                    return;
                end = p.cursor;
            } else if (p.body == Body::Close) {
                if (!input.endKnown)
                    return;
                end = bytes.size();
            }
            p.message.bytes = input.bytes;
            p.message.offset = 0;
            p.message.length = end;
            p.message.status = AnalysisStatus::Complete;
            p.message.sources = messageSources(input, 0, end);
            detail::freezeMessage(p.message, buffer.base);
            detail::appendStreamMessage(result, std::move(p.message), droppedThrough);
            if (response && (p.status >= 200 || p.status == 101) && !requests.empty())
                requests.pop_front();
            done[side] = response && (p.status == 101 ||
                                      (p.method == "CONNECT" && p.status >= 200 && p.status < 300));
            pending[side].reset();
            buffer.consume(end);
        }
    }
};
Http1Stream::Http1Stream() : impl_(std::make_unique<Impl>()) {}
Http1Stream::~Http1Stream() = default;
ApplicationResult Http1Stream::append(const std::array<ApplicationInput, 2> &input,
                                      std::stop_token stop) {
    auto &state = *impl_;
    try {
        if (!state.failed) {
            for (unsigned side = 0; side < 2; ++side)
                state.buffers[side].append(input[side]);
            if (!state.client)
                for (unsigned side = 0; side < 2; ++side) {
                    const auto &bytes = *state.buffers[side].data.bytes;
                    const std::string_view text(reinterpret_cast<const char *>(bytes.data()),
                                                bytes.size());
                    if (text.find("\r\n") != std::string_view::npos) {
                        state.client = text.starts_with("HTTP/1.") ? 1 - side : side;
                        break;
                    }
                }
            if (state.client) {
                state.process(*state.client, stop);
                state.process(1 - *state.client, stop);
            }
        }
    } catch (const std::length_error &error) {
        state.failed = true;
        state.result.status = AnalysisStatus::Limited;
        state.result.error = error.what();
    } catch (const std::exception &error) {
        state.failed = true;
        state.result.status = AnalysisStatus::Incomplete;
        state.result.error = error.what();
    }
    auto snapshot = state.result;
    for (unsigned side = 0; side < 2; ++side) {
        if (state.pending[side]) {
            auto message = state.pending[side]->message;
            message.bytes = state.buffers[side].data.bytes;
            message.length = state.buffers[side].size();
            message.status = AnalysisStatus::Incomplete;
            message.sources = messageSources(state.buffers[side].data, 0, message.length);
            try {
                detail::freezeMessage(message, state.buffers[side].base);
                appendApplicationMessage(snapshot, std::move(message));
            } catch (const std::length_error &error) {
                snapshot.status = AnalysisStatus::Limited;
                snapshot.error = error.what();
            }
        }
        if ((state.buffers[side].size() || state.buffers[side].data.incomplete) &&
            snapshot.status == AnalysisStatus::Complete)
            snapshot.status = AnalysisStatus::Incomplete;
    }
    if (state.droppedThrough && state.droppedThrough >= state.retentionFloor) {
        snapshot.status = AnalysisStatus::Limited;
        snapshot.error = "Application result limit reached";
    }
    snapshot.estimatedBytes = estimateApplicationBytes(snapshot);
    return snapshot;
}
void Http1Stream::prune(std::uint64_t first) {
    impl_->retentionFloor = first;
    detail::pruneMessages(impl_->result, first);
}
std::size_t Http1Stream::estimatedBytes() const {
    std::size_t bytes = sizeof(Impl) + estimateApplicationBytes(impl_->result);
    for (unsigned side = 0; side < 2; ++side) {
        bytes += impl_->buffers[side].estimatedBytes();
        if (impl_->pending[side]) {
            ApplicationResult pending;
            pending.messages.push_back(impl_->pending[side]->message);
            bytes += estimateApplicationBytes(pending);
        }
    }
    for (const auto &request : impl_->requests)
        bytes += sizeof(Request) + request.method.capacity() + 32;
    return bytes;
}
} // namespace etherscope
