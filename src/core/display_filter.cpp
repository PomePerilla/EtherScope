#include "core/display_filter.h"
#include "core/filter.h"
#include <algorithm>
#include <charconv>
#include <cctype>

namespace etherscope {
namespace {
enum class Kind { Number, Boolean, Text, Ip4, Ip6, Mac };
struct Definition {
    Kind kind;
    bool application{};
};
const std::map<std::string, Definition> &definitions() {
    static const auto result = [] {
        std::map<std::string, Definition> d;
        for (const auto *n :
             {"frame.number", "frame.len", "frame.cap_len", "frame.interface_id", "tcp.srcport",
              "tcp.dstport", "tcp.port", "udp.srcport", "udp.dstport", "udp.port", "tcp.flags",
              "tcp.stream", "icmp.type", "icmpv6.type"})
            d[n] = {Kind::Number, false};
        for (const auto *n : {"eth", "ip", "ipv6", "tcp", "udp", "arp", "icmp", "icmpv6",
                              "packet.error", "packet.warning", "tcp.flags.syn", "tcp.flags.ack",
                              "tcp.flags.fin", "tcp.flags.reset"})
            d[n] = {Kind::Boolean, false};
        for (const auto *n : {"eth.src", "eth.dst", "eth.addr"})
            d[n] = {Kind::Mac, false};
        for (const auto *n : {"ip.src", "ip.dst", "ip.addr"})
            d[n] = {Kind::Ip4, false};
        for (const auto *n : {"ipv6.src", "ipv6.dst", "ipv6.addr"})
            d[n] = {Kind::Ip6, false};
        for (const auto *n : {"dns", "http", "http2", "tls", "dns.flags.response", "tls.decrypted"})
            d[n] = {Kind::Boolean, true};
        for (const auto *n : {"dns.id", "dns.qry.type", "dns.flags.rcode", "http.response.code",
                              "http2.streamid", "tls.version", "tls.cipher"})
            d[n] = {Kind::Number, true};
        for (const auto *n : {"dns.qry.name", "dns.resp.name", "http.request.method",
                              "http.request.uri", "http.host", "tls.sni", "tls.alpn", "tls.status"})
            d[n] = {Kind::Text, true};
        d["dns.a"] = {Kind::Ip4, true};
        d["dns.aaaa"] = {Kind::Ip6, true};
        return d;
    }();
    return result;
}
struct Token {
    std::string value;
    std::size_t position{};
    bool quoted{};
};
struct Error {
    std::size_t position;
    std::string message;
};
std::vector<Token> lex(std::string_view text) {
    std::vector<Token> result;
    for (std::size_t at = 0; at < text.size();) {
        if (std::isspace(static_cast<unsigned char>(text[at]))) {
            ++at;
            continue;
        }
        const auto start = at;
        const char c = text[at++];
        if (c == '\'' || c == '"') {
            std::string value;
            bool ended = false;
            while (at < text.size()) {
                char ch = text[at++];
                if (ch == c) {
                    ended = true;
                    break;
                }
                if (ch == '\\') {
                    if (at == text.size())
                        break;
                    ch = text[at++];
                    if (ch == 'n')
                        ch = '\n';
                    else if (ch == 'r')
                        ch = '\r';
                    else if (ch == 't')
                        ch = '\t';
                    else if (ch != '\\' && ch != '\'' && ch != '"')
                        throw Error{at - 1, "Invalid string escape"};
                }
                value += ch;
            }
            if (!ended)
                throw Error{start, "Unterminated string"};
            result.push_back({std::move(value), start, true});
        } else if (std::string_view("(){}!,<>=&|").find(c) != std::string_view::npos) {
            std::string value(1, c);
            if (at < text.size() &&
                ((text[at] == '=' && std::string_view("!<>=").find(c) != std::string_view::npos) ||
                 (text[at] == c && (c == '&' || c == '|'))))
                value += text[at++];
            result.push_back({value, start, false});
        } else {
            while (at < text.size() && !std::isspace(static_cast<unsigned char>(text[at])) &&
                   std::string_view("(){}!,<>=&|").find(text[at]) == std::string_view::npos)
                ++at;
            result.push_back({std::string(text.substr(start, at - start)), start, false});
        }
        if (result.size() > 1024)
            throw Error{start, "Expression token limit reached"};
    }
    result.push_back({"", text.size(), false});
    return result;
}
struct Literal {
    ApplicationValue value;
    std::vector<std::uint8_t> address;
    std::optional<unsigned> prefix;
};
struct Node {
    enum class Type { Predicate, And, Or, Not } type{Type::Predicate};
    std::size_t a{}, b{};
    std::string field, operation;
    std::vector<Literal> values;
};
Literal literal(const Token &token, Kind kind) {
    Literal result;
    if (kind == Kind::Text) {
        result.value = token.value;
        return result;
    }
    if (kind == Kind::Boolean) {
        if (token.value != "true" && token.value != "false")
            throw Error{token.position, "Boolean value expected"};
        result.value = token.value == "true";
        return result;
    }
    if (kind == Kind::Number) {
        std::uint64_t value = 0;
        auto text = std::string_view(token.value);
        int base = 10;
        if (text.starts_with("0x")) {
            base = 16;
            text.remove_prefix(2);
        }
        const auto [p, e] = std::from_chars(text.data(), text.data() + text.size(), value, base);
        if (e != std::errc{} || p != text.data() + text.size() || text.empty())
            throw Error{token.position, "Unsigned number expected"};
        result.value = value;
        return result;
    }
    auto text = token.value;
    const auto slash = text.find('/');
    if (slash != std::string::npos) {
        if (kind == Kind::Mac)
            throw Error{token.position, "CIDR requires an IP address"};
        unsigned prefix = 0;
        auto part = std::string_view(text).substr(slash + 1);
        const auto [p, e] = std::from_chars(part.data(), part.data() + part.size(), prefix);
        if (e != std::errc{} || p != part.data() + part.size() || part.empty() ||
            prefix > (kind == Kind::Ip4 ? 32u : 128u))
            throw Error{token.position, "Invalid CIDR prefix"};
        result.prefix = prefix;
        text.resize(slash);
    }
    const auto parsed = parseFilter(kind == Kind::Mac ? text : "", Direction::Either,
                                    kind == Kind::Mac ? "" : text, Direction::Either);
    if (!parsed.value)
        throw Error{token.position, "Invalid address"};
    if (kind == Kind::Mac && parsed.value->mac)
        result.address.assign(parsed.value->mac->begin(), parsed.value->mac->end());
    else if (kind == Kind::Ip4 && parsed.value->ip)
        result.address.assign(parsed.value->ip->begin(), parsed.value->ip->end());
    else if (kind == Kind::Ip6 && parsed.value->ipv6)
        result.address.assign(parsed.value->ipv6->begin(), parsed.value->ipv6->end());
    else
        throw Error{token.position, "Address family differs"};
    result.value = text;
    return result;
}
class Parser {
  public:
    explicit Parser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}
    std::vector<Node> nodes;
    bool application{};
    std::size_t parse() {
        const auto root = expression(0);
        if (!peek().value.empty())
            throw Error{peek().position, "Unexpected token"};
        return root;
    }

  private:
    std::vector<Token> tokens_;
    std::size_t at_{};
    const Token &peek() const {
        return tokens_[at_];
    }
    bool take(std::string_view value) {
        if (!peek().quoted && peek().value == value) {
            ++at_;
            return true;
        }
        return false;
    }
    std::size_t append(Node node) {
        if (nodes.size() >= 512)
            throw Error{peek().position, "Expression node limit reached"};
        nodes.push_back(std::move(node));
        return nodes.size() - 1;
    }
    std::size_t expression(unsigned depth) {
        auto a = conjunction(depth);
        while (take("or") || take("||")) {
            auto b = conjunction(depth);
            Node n;
            n.type = Node::Type::Or;
            n.a = a;
            n.b = b;
            a = append(std::move(n));
        }
        return a;
    }
    std::size_t conjunction(unsigned depth) {
        auto a = unary(depth);
        while (take("and") || take("&&")) {
            auto b = unary(depth);
            Node n;
            n.type = Node::Type::And;
            n.a = a;
            n.b = b;
            a = append(std::move(n));
        }
        return a;
    }
    std::size_t unary(unsigned depth) {
        if (depth >= 32)
            throw Error{peek().position, "Expression nesting limit reached"};
        if (take("not") || take("!")) {
            Node n;
            n.type = Node::Type::Not;
            n.a = unary(depth + 1);
            return append(std::move(n));
        }
        if (take("(")) {
            const auto root = expression(depth + 1);
            if (!take(")"))
                throw Error{peek().position, "Closing parenthesis expected"};
            return root;
        }
        const auto name = peek();
        const auto found = definitions().find(name.value);
        if (name.quoted || found == definitions().end())
            throw Error{name.position, "Unknown field"};
        ++at_;
        application |= found->second.application;
        Node n;
        n.field = name.value;
        if (peek().value == "==" || peek().value == "!=" || peek().value == "<" ||
            peek().value == ">" || peek().value == "<=" || peek().value == ">=" ||
            peek().value == "contains" || peek().value == "in") {
            n.operation = peek().value;
            ++at_;
            if (n.operation == "contains" && found->second.kind != Kind::Text)
                throw Error{peek().position, "contains requires a text field"};
            if (n.operation == "in") {
                if (!take("{"))
                    throw Error{peek().position, "Value set expected"};
                do {
                    if (peek().value.empty())
                        throw Error{peek().position, "Value expected"};
                    n.values.push_back(literal(peek(), found->second.kind));
                    ++at_;
                    if (n.values.size() > 512)
                        throw Error{peek().position, "Value set limit reached"};
                } while (take(","));
                if (!take("}"))
                    throw Error{peek().position, "Closing brace expected"};
            } else {
                if (peek().value.empty())
                    throw Error{peek().position, "Value expected"};
                n.values.push_back(literal(peek(), found->second.kind));
                ++at_;
            }
            if (found->second.kind == Kind::Boolean && n.operation != "==" && n.operation != "!=" &&
                n.operation != "in")
                throw Error{name.position, "Invalid boolean comparison"};
            if ((found->second.kind == Kind::Ip4 || found->second.kind == Kind::Ip6 ||
                 found->second.kind == Kind::Mac) &&
                n.operation != "==" && n.operation != "!=" && n.operation != "in")
                throw Error{name.position, "Invalid address comparison"};
        }
        return append(std::move(n));
    }
};
struct Values {
    std::vector<ApplicationValue> items;
    bool known{true};
};
Values resolve(const std::string &name, const Packet &p, const ApplicationFacts *facts) {
    Values result;
    auto add = [&](ApplicationValue value) { result.items.push_back(std::move(value)); };
    const auto def = definitions().at(name);
    if (def.application) {
        if (facts) {
            const auto found = facts->values.find(name);
            if (found != facts->values.end())
                result.items = found->second;
            result.known = facts->status == AnalysisStatus::Complete;
        } else
            result.known = (!p.tcp || !p.tcp->payloadLength) &&
                           (!p.udp || (p.udp->sourcePort != 53 && p.udp->destinationPort != 53));
        return result;
    }
    if (name == "frame.number")
        add(p.id);
    else if (name == "frame.len")
        add(std::uint64_t(p.raw.originalLength));
    else if (name == "frame.cap_len")
        add(std::uint64_t(p.raw.bytes.size()));
    else if (name == "frame.interface_id")
        add(std::uint64_t(p.raw.interfaceId));
    else if (name == "packet.error")
        add(!p.error.empty());
    else if (name == "packet.warning")
        add(!p.warnings.empty());
    else if (name == "eth")
        add(bool(p.sourceMac && p.destinationMac));
    else if (name == "ip")
        add(bool(p.sourceIp || p.destinationIp));
    else if (name == "ipv6")
        add(bool(p.sourceIpv6 || p.destinationIpv6));
    else if (name == "tcp")
        add(bool(p.tcp));
    else if (name == "udp")
        add(bool(p.udp));
    else if (name == "arp")
        add(p.protocol == "ARP");
    else if (name == "icmp")
        add(p.protocol == "ICMP");
    else if (name == "icmpv6")
        add(p.protocol == "ICMPv6");
    else if (name == "icmp.type" || name == "icmpv6.type") {
        if (p.icmpType && p.protocol == (name == "icmp.type" ? "ICMP" : "ICMPv6"))
            add(std::uint64_t(*p.icmpType));
    } else if (name.starts_with("tcp.") && p.tcp) {
        const auto &t = *p.tcp;
        if (name == "tcp.srcport" || name == "tcp.port")
            add(std::uint64_t(t.sourcePort));
        if (name == "tcp.dstport" || name == "tcp.port")
            add(std::uint64_t(t.destinationPort));
        if (name == "tcp.stream")
            add(p.tcpConversationId);
        if (name == "tcp.flags")
            add(std::uint64_t(t.flags));
        if (name == "tcp.flags.syn")
            add(bool(t.flags & 2));
        if (name == "tcp.flags.ack")
            add(bool(t.flags & 16));
        if (name == "tcp.flags.fin")
            add(bool(t.flags & 1));
        if (name == "tcp.flags.reset")
            add(bool(t.flags & 4));
    } else if (name.starts_with("udp.") && p.udp) {
        if (name == "udp.srcport" || name == "udp.port")
            add(std::uint64_t(p.udp->sourcePort));
        if (name == "udp.dstport" || name == "udp.port")
            add(std::uint64_t(p.udp->destinationPort));
    } else if (name.starts_with("eth.")) {
        if ((name == "eth.src" || name == "eth.addr") && p.sourceMac)
            add(formatMac(*p.sourceMac));
        if ((name == "eth.dst" || name == "eth.addr") && p.destinationMac)
            add(formatMac(*p.destinationMac));
    } else if (name.starts_with("ip.")) {
        if ((name == "ip.src" || name == "ip.addr") && p.sourceIp)
            add(formatIp(*p.sourceIp));
        if ((name == "ip.dst" || name == "ip.addr") && p.destinationIp)
            add(formatIp(*p.destinationIp));
    } else if (name.starts_with("ipv6.")) {
        if ((name == "ipv6.src" || name == "ipv6.addr") && p.sourceIpv6)
            add(formatIpv6(*p.sourceIpv6));
        if ((name == "ipv6.dst" || name == "ipv6.addr") && p.destinationIpv6)
            add(formatIpv6(*p.destinationIpv6));
    }
    return result;
}
bool compare(const ApplicationValue &actual, const Literal &expected, Kind kind,
             const std::string &op) {
    bool equal = false;
    int order = 0;
    if (!expected.address.empty()) {
        const auto *text = std::get_if<std::string>(&actual);
        if (!text)
            return false;
        Literal parsed;
        try {
            parsed = literal({*text, 0, false}, kind);
        } catch (...) {
            return false;
        }
        if (parsed.address.size() != expected.address.size())
            return false;
        unsigned bits =
            expected.prefix.value_or(static_cast<unsigned>(expected.address.size() * 8));
        equal = true;
        for (std::size_t i = 0; i < parsed.address.size() && bits; ++i) {
            const auto used = std::min(8u, bits);
            const auto mask = static_cast<std::uint8_t>(255u << (8 - used));
            if ((parsed.address[i] & mask) != (expected.address[i] & mask)) {
                equal = false;
                break;
            }
            bits -= used;
        }
    } else {
        if (actual.index() != expected.value.index())
            return false;
        equal = actual == expected.value;
        if (op == "contains") {
            const auto *text = std::get_if<std::string>(&actual);
            return text && text->find(std::get<std::string>(expected.value)) != std::string::npos;
        }
        order = actual < expected.value ? -1 : (equal ? 0 : 1);
    }
    if (op == "==" || op == "in")
        return equal;
    if (op == "!=")
        return !equal;
    if (op == "<")
        return order < 0;
    if (op == "<=")
        return order <= 0;
    if (op == ">")
        return order > 0;
    if (op == ">=")
        return order >= 0;
    return false;
}
} // namespace
struct DisplayExpression::Implementation {
    std::vector<Node> nodes;
    std::size_t root{};
};
DisplayExpression::DisplayExpression(std::string source,
                                     std::shared_ptr<const Implementation> implementation,
                                     bool application)
    : source_(std::move(source)), implementation_(std::move(implementation)),
      application_(application) {}
FilterTruth DisplayExpression::evaluate(const Packet &packet, const ApplicationFacts *facts) const {
    auto visit = [&](auto &&self, std::size_t index) -> FilterTruth {
        const auto &n = implementation_->nodes[index];
        if (n.type != Node::Type::Predicate) {
            const auto a = self(self, n.a);
            if (n.type == Node::Type::Not)
                return a == FilterTruth::Unknown
                           ? a
                           : (a == FilterTruth::True ? FilterTruth::False : FilterTruth::True);
            if ((n.type == Node::Type::And && a == FilterTruth::False) ||
                (n.type == Node::Type::Or && a == FilterTruth::True))
                return a;
            const auto b = self(self, n.b);
            if (n.type == Node::Type::And) {
                if (b == FilterTruth::False)
                    return b;
                return a == FilterTruth::Unknown || b == FilterTruth::Unknown ? FilterTruth::Unknown
                                                                              : FilterTruth::True;
            }
            if (b == FilterTruth::True)
                return b;
            return a == FilterTruth::Unknown || b == FilterTruth::Unknown ? FilterTruth::Unknown
                                                                          : FilterTruth::False;
        }
        const auto values = resolve(n.field, packet, facts);
        const auto kind = definitions().at(n.field).kind;
        for (const auto &actual : values.items) {
            if (n.operation.empty()) {
                if (kind != Kind::Boolean || std::get<bool>(actual))
                    return FilterTruth::True;
            } else
                for (const auto &expected : n.values)
                    if (compare(actual, expected, kind, n.operation))
                        return FilterTruth::True;
        }
        return values.known ? FilterTruth::False : FilterTruth::Unknown;
    };
    return visit(visit, implementation_->root);
}
DisplayFilterResult compileDisplayFilter(std::string_view source) {
    try {
        if (source.size() > 4096)
            throw Error{4096, "Expression length limit reached"};
        Parser parser(lex(source));
        auto implementation = std::make_shared<DisplayExpression::Implementation>();
        implementation->root = parser.parse();
        implementation->nodes = std::move(parser.nodes);
        return {std::make_shared<DisplayExpression>(std::string(source), std::move(implementation),
                                                    parser.application),
                {},
                0};
    } catch (const Error &error) {
        return {{}, error.message, error.position};
    } catch (const std::exception &) {
        return {{}, "Invalid expression", 0};
    }
}
} // namespace etherscope
