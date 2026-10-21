# EtherScope v1.9.0

[English](README.md) | 简体中文 | [繁體中文](README.zh-TW.md)

Windows x64 网络协议分析器。

- Ethernet、VLAN、IPv4、IPv6、ICMP、ICMPv6、ARP、TCP、UDP。
- BPF 捕获过滤、地址与协议显示过滤、PCAP 文件。
- 数据包列表、字段与原始字节联动，后台导出。
- TCP 会话、握手、流重组与关联报文定位。
- English、简体中文、繁體中文。

## 下载

[EtherScope v1.9.0](https://github.com/PomePerilla/EtherScope/releases/tag/v1.9.0)

| 文件 | 用途 |
|---|---|
| `EtherScope-1.9.0-windows-x64.zip` | 安装后使用 |
| `EtherScope-1.9.0-sourcecode.zip` | 编译后使用 |

1. 安装 [Npcap 1.89](https://npcap.com/dist/npcap-1.89.exe)。
2. 解压程序包，运行安装器。
3. 打开 EtherScope，选择网卡，开始。

## 使用

| 操作 | 入口 |
|---|---|
| 语言 | 更多 > 语言 |
| 捕获过滤 | 更多 > 捕获过滤 |
| TCP 分析 | 更多 > TCP 会话 > 流数据 |
| 打开 / 保存 | Ctrl+O / Ctrl+S |
| 应用地址条件 | Ctrl+Enter |

## 编译

C++20, MSVC 2022 x64, Qt 6.8.3, CMake 3.24+, Npcap SDK 1.16.

```powershell
.\scripts\build.ps1 -Clean -Test -QtRoot 'C:\Qt\6.8.3\msvc2022_64' -NpcapSdkRoot 'C:\SDK\npcap-sdk-1.16'
```

## 测试

```powershell
python tests/check_translations.py
```

构建脚本执行核心与界面测试。GitHub Actions 执行 ASan、UBSan、静态检查和模糊测试。

## 许可

[MIT](LICENSE)。[第三方组件](THIRD_PARTY_NOTICES.md)。
