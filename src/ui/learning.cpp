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
        description = "A MAC address identifies a link-layer interface. Source and destination show the sender and receiver on this link.";
    else if (key == "eth.type")
        description = "EtherType identifies the encapsulated protocol. A VLAN tag adds another encapsulation header.";
    else if (key == "vlan.id")
        description = "The VLAN ID identifies the logical network carried by this VLAN tag.";
    else if (key == "ip.src" || key == "ip.dst" || key == "ipv6.src" || key == "ipv6.dst")
        description = "Source and destination identify the sender and receiver in this IP header. NAT and tunnels can change the addresses along the path.";
    else if (key == "ip.ttl" || key == "ipv6.hlim")
        description = "TTL or Hop Limit decreases at each forwarding router. A router discards the packet when this value reaches zero.";
    else if (key == "ip.len" || key == "ipv6.plen")
        description = "IPv4 total length counts the header and payload in bytes. IPv6 payload length counts the bytes after the base header.";
    else if (key.endsWith(".checksum"))
        description = "A checksum helps detect data errors. Read the verification result alongside this value; network-card offloading can affect captured checksums.";
    else if (key.endsWith(".srcport") || key.endsWith(".dstport"))
        description = "Ports identify transport endpoints. Source and destination ports distinguish the sending and receiving services.";
    else if (key == "tcp.seq" || key == "tcp.ack")
        description = "TCP sequence numbers track byte positions, and acknowledgments identify the next expected byte. Values here use absolute numbering.";
    else if (key == "tcp.flags")
        description = "SYN starts synchronization, ACK marks a valid acknowledgment, FIN ends a byte stream, and RST resets a connection.";
    else if (key == "tcp.window_size")
        description = "The receive window advertises available receive capacity. This value is the raw header field before window scaling.";
    else if (key == "udp.length")
        description = "UDP length counts the 8-byte header and payload in bytes.";
    else if (key == "icmp.type" || key == "icmp.code" || key == "icmpv6.type" || key == "icmpv6.code")
        description = "ICMP Type selects the message category and Code refines its meaning. ICMP and ICMPv6 use different number assignments.";
    else if (key == "dns.qry.name")
        description = "The DNS question name is the domain name requested by the client. Match the transaction ID to inspect its response.";
    else if (key == "http.host")
        description = "Host specifies the target host and optional port of an HTTP request.";
    else if (key == "tls.sni")
        description = "SNI carries the server name requested in TLS ClientHello, allowing a server to select the matching site.";
    if (!description)
        return i18n::text("此字段暂无说明，仍可复制和查看对应字节");
    return i18n::text("当前值: %1").arg(value) + "\n" + i18n::text(description);
}
QString statusExplanation(AnalysisStatus status) {
    switch (status) {
    case AnalysisStatus::Pending:
        return i18n::text("Analysis is waiting for background work or more captured data. Fields update as parsing progresses.");
    case AnalysisStatus::Complete:
        return i18n::text("Parsing is complete. Inspect the message fields and bytes.");
    case AnalysisStatus::Incomplete:
        return i18n::text("Message data is incomplete. Check stream gaps or continue capturing.");
    case AnalysisStatus::Limited:
        return i18n::text("An analysis resource limit was reached. Narrow the filter or capture a shorter session.");
    case AnalysisStatus::MissingKeys:
        return i18n::text("Decryption needs a matching TLS key log. Open the key-log settings, then load or reload keys supplied by the endpoint.");
    case AnalysisStatus::Unsupported:
        return i18n::text("This protocol feature is not supported yet. Inspect the original or reassembled bytes.");
    case AnalysisStatus::AuthenticationFailed:
        return i18n::text("Decryption authentication failed. Check matching keys and stream completeness.");
    }
    return {};
}
} // namespace etherscope::learning
