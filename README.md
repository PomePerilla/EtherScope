# EtherScope v1.9.0

English | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

Windows x64 network protocol analyzer.

- Ethernet, VLAN, IPv4, IPv6, ICMP, ICMPv6, ARP, TCP and UDP.
- BPF capture filters, address and protocol display filters, PCAP files.
- Linked packet list, fields and raw bytes, asynchronous export.
- TCP conversations, handshakes, stream reassembly and packet-linked markers.
- English, Simplified Chinese and Traditional Chinese.

## Download

[EtherScope v1.9.0](https://github.com/PomePerilla/EtherScope/releases/tag/v1.9.0)

| File | Use |
|---|---|
| `EtherScope-1.9.0-windows-x64.zip` | Install and run |
| `EtherScope-1.9.0-sourcecode.zip` | Build from source |

1. Install [Npcap 1.89](https://npcap.com/dist/npcap-1.89.exe).
2. Extract the program package and run the installer.
3. Open EtherScope, select an interface, then Start.

## Use

| Action | Entry |
|---|---|
| Language | More > Language |
| Capture filter | More > Capture filter |
| TCP analysis | More > TCP conversations > Stream data |
| Open / Save | Ctrl+O / Ctrl+S |
| Apply addresses | Ctrl+Enter |

## Build

C++20, MSVC 2022 x64, Qt 6.8.3, CMake 3.24+, Npcap SDK 1.16.

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
