#include "ui/learning.h"
#include "ui/language.h"
#include "core/display_filter.h"
namespace etherscope::learning {
QString quoted(const QString &text) {
    auto escaped = text;
    escaped.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
        .replace('\r', "\\r").replace('\t', "\\t");
    return '"' + escaped + '"';
}
QString fieldPredicate(const QString &key, const ApplicationValue &value) {
    if (key.isEmpty())
        return {};
    QString literal;
    if (const auto *number = std::get_if<std::uint64_t>(&value))
        literal = QString::number(*number);
    else if (const auto *flag = std::get_if<bool>(&value))
        literal = *flag ? "true" : "false";
    else {
        const auto text = QString::fromStdString(std::get<std::string>(value));
        literal = key.startsWith("ip.") || key.startsWith("ipv6.") || key.startsWith("eth.")
                      ? text : quoted(text);
    }
    const auto result = key + " == " + literal;
    return compileDisplayFilter(result.toStdString()).value ? result : QString{};
}
QString fieldExplanation(const QString &key, const QString &value) {
    const char *description = nullptr;
    if (key == "eth.src" || key == "eth.dst")
        description = "A link-layer address identifies an interface on this link; it does not identify a person or a remote IP host.";
    else if (key == "eth.type")
        description = "EtherType identifies the encapsulated protocol. A VLAN tag adds another encapsulation header.";
    else if (key == "vlan.id")
        description = "The VLAN ID separates logical link-layer networks. This value describes the decoded tag, not an inferred network topology.";
    else if (key == "ip.src" || key == "ip.dst" || key == "ipv6.src" || key == "ipv6.dst")
        description = "The source and destination are the addresses in this IP header. NAT, tunnels and quoted headers can describe different endpoints.";
    else if (key == "ip.ttl" || key == "ipv6.hlim")
        description = "TTL or Hop Limit is reduced by forwarding routers. A low value alone does not prove packet loss or a routing fault.";
    else if (key == "ip.len" || key == "ipv6.plen")
        description = "IPv4 total length includes its header; IPv6 payload length excludes the base header. Captured bytes may be truncated.";
    else if (key.endsWith(".checksum"))
        description = "A checksum detects some transmission errors. Offloading and truncated captures can affect verification; an unverified value is not evidence of corruption.";
    else if (key.endsWith(".srcport") || key.endsWith(".dstport"))
        description = "Ports identify transport endpoints. A familiar port number suggests a convention, but does not prove which application is present.";
    else if (key == "tcp.seq" || key == "tcp.ack")
        description = "TCP sequence numbers track byte positions; acknowledgments normally identify the next expected byte. These are captured absolute values, not relative numbering.";
    else if (key == "tcp.flags")
        description = "SYN starts synchronization, ACK validates the acknowledgment field, FIN ends a byte stream, and RST resets a connection. One observed flag does not prove the full connection state.";
    else if (key == "tcp.window_size")
        description = "The advertised receive window limits outstanding data. This is the raw header value; negotiated window scaling is not applied here.";
    else if (key == "udp.length")
        description = "UDP length includes the 8-byte UDP header and payload. Fragmentation or capture truncation can make the available bytes shorter.";
    else if (key == "icmp.type" || key == "icmp.code" || key == "icmpv6.type" || key == "icmpv6.code")
        description = "ICMP Type selects the message category and Code refines its meaning. ICMP and ICMPv6 use different number assignments.";
    else if (key == "dns.qry.name")
        description = "The DNS question name is the name being queried. A captured query does not establish that a response was received or a connection succeeded.";
    else if (key == "http.host")
        description = "Host is the HTTP request authority field observed by the parser. Its presence does not prove the destination server identity.";
    else if (key == "tls.sni")
        description = "SNI is the server name requested in the observed TLS ClientHello. It is not certificate validation or proof of a completed TLS handshake.";
    if (!description)
        return i18n::text("此字段暂无说明，仍可复制和查看对应字节");
    return i18n::text("当前值: %1").arg(value) + "\n" + i18n::text(description);
}
QString statusExplanation(AnalysisStatus status) {
    switch (status) {
    case AnalysisStatus::Pending:
        return i18n::text("Analysis is waiting for background work or more captured data. Application fields may still be unknown.");
    case AnalysisStatus::Complete:
        return i18n::text("The available message was parsed. This does not certify that the network transaction succeeded.");
    case AnalysisStatus::Incomplete:
        return i18n::text("Some message bytes or boundaries are missing. Check capture coverage and stream gaps; do not treat missing fields as absent.");
    case AnalysisStatus::Limited:
        return i18n::text("An analysis resource limit was reached. Narrow the capture or start a shorter session; this is separate from capture packet drops.");
    case AnalysisStatus::MissingKeys:
        return i18n::text("Decryption needs a matching TLS key log. Open the key-log settings, then load or reload keys supplied by the endpoint.");
    case AnalysisStatus::Unsupported:
        return i18n::text("The observed protocol feature is outside the implemented parser. Inspect the raw or reassembled bytes.");
    case AnalysisStatus::AuthenticationFailed:
        return i18n::text("Authenticated decryption failed. Check matching keys and stream completeness; this alone does not establish an attack.");
    }
    return {};
}
} // namespace etherscope::learning
