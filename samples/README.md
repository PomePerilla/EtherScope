# 样本

| 文件 | 来源 | 包数 |
|---|---|---|
| `synthetic-protocols.pcap` | 构造 | 12 |
| `synthetic-ipv6.pcap` | 构造 | 21 |

## IPv4

| 序号 | 内容 |
|---|---|
| 1 | ICMP回显请求，Type 8 / Code 0 |
| 2 | ICMP回显应答，Type 0 / Code 0 |
| 3 | ICMP时间超过，Type 11 / Code 0 |
| 4 | ICMP目的地址不可达，Type 3 / Code 3 |
| 5 | ARP请求 |
| 6 | TCP SYN，MSS选项 |
| 7 | UDP |
| 8 | IPv4选项 / ICMP |
| 9 | VLAN 42 / IPv4 / ICMP |
| 10 | IPv4非首片 |
| 11 | EtherType 0x88B5 |
| 12 | IPv4 / ICMP截断记录 |

## IPv6

| 序号 | 内容 |
|---|---|
| 1-2 | ICMPv6回显请求、应答 |
| 3-4 | TCP SYN、UDP |
| 5 | Hop-by-Hop / Routing / Destination Options / UDP |
| 6-8 | 首片、非首片、原子分片 |
| 9 | AH / TCP |
| 10-11 | ESP、No Next Header |
| 12-16 | 邻居请求、邻居通告、路由器请求、路由器通告、重定向 |
| 17-20 | 目的不可达、数据包过大、时间超过、参数问题 |
| 21 | VLAN 42 / IPv6 / ICMPv6 |
