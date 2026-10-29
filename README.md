# EtherScope v2.3.0

English | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

Windows x64 network protocol analyzer.

- Ethernet, VLAN, IPv4, IPv6, ICMP, ICMPv6, ARP, TCP and UDP.
- BPF capture filters, address and protocol display filters, PCAP and PCAPNG files.
- Linked packet list, fields and raw bytes, asynchronous export.
- TCP conversations, handshakes, reassembly and incremental application analysis.
- DNS, HTTP/1.x, HTTP/2, TLS metadata and key-log decryption.
- Rolling PCAPNG recording and typed display expressions.
- English, Simplified Chinese and Traditional Chinese.
- Network and loopback capture.
- Packet and field context actions, display-filter undo and recent history.
- Source-bound TCP/application panels that dock or float, with optional field and analysis explanations.
- Incremental message updates preserve field selection, byte pages and reading position.
- Find text or hexadecimal bytes, navigate reading history, and inspect grouped capture and analysis diagnostics.

## Download

[EtherScope v2.3.0](https://github.com/PomePerilla/EtherScope/releases/tag/v2.3.0)

| File | Use |
|---|---|
| `EtherScope-2.3.0-windows-x64.zip` | Install and run |
| `EtherScope-2.3.0-sourcecode.zip` | Build from source |

1. Install [Npcap 1.89](https://npcap.com/dist/npcap-1.89.exe).
2. Extract the program package and run the installer.
3. Open EtherScope, select an interface, then Start.

## Use

| Action | Entry |
|---|---|
| Language | More > Appearance and language > Language |
| Capture filter | More > Capture settings > Capture filter |
| TCP analysis | Analysis > TCP conversations > Stream data |
| Application messages | Analysis > Application analysis |
| TLS keys | More > TLS key log |
| Recording | More > Capture settings > Recording settings, Record to disk |
| Display expression | Filter toolbar > Display expression |
| Open / Save | Ctrl+O / Ctrl+S |
| Apply addresses | Ctrl+Enter |

Documentation: [Search workspace](docs/检索与排查工作区.md), [Release notes](docs/发布说明-2.3.0.md), and [Course requirements audit](docs/课程要求核对.md).

## Build

C++20, MSVC 2022 x64, Qt 6.8.3, CMake 3.24+, Npcap SDK 1.16. OpenSSL 3.5.9 and nghttp2 1.70.0 are built by the script.

```powershell
.\scripts\build.ps1 -Clean -Test -QtRoot 'C:\Qt\6.8.3\msvc2022_64' -NpcapSdkRoot 'C:\SDK\npcap-sdk-1.16'
```

## Tests

```powershell
python tests/check_translations.py
```

The build script runs the core and desktop tests. GitHub Actions also runs ASan, UBSan, static analysis and fuzz tests.

## License

[MIT](LICENSE). [Third-party notices](THIRD_PARTY_NOTICES.md).
