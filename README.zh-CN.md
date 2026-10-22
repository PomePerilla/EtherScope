# EtherScope v2.1.0

[English](README.md) | 简体中文 | [繁體中文](README.zh-TW.md)

Windows x64 网络协议分析器。

- Ethernet、VLAN、IPv4、IPv6、ICMP、ICMPv6、ARP、TCP、UDP。
- BPF 捕获过滤、地址与协议显示过滤、PCAP 和 PCAPNG 文件。
- 数据包列表、字段与原始字节联动，后台导出。
- TCP 会话、握手、流重组与应用层增量分析。
- DNS、HTTP/1.x、HTTP/2、TLS 元数据与密钥日志解密。
- PCAPNG 滚动录制与显示表达式。
- English、简体中文、繁體中文。
- 网卡与回环抓包。

## 下载

[EtherScope v2.1.0](https://github.com/PomePerilla/EtherScope/releases/tag/v2.1.0)

| 文件 | 用途 |
|---|---|
| `EtherScope-2.1.0-windows-x64.zip` | 安装后使用 |
| `EtherScope-2.1.0-sourcecode.zip` | 编译后使用 |

1. 安装 [Npcap 1.89](https://npcap.com/dist/npcap-1.89.exe)。
2. 解压程序包，运行安装器。
3. 打开 EtherScope，选择网卡，开始。

## 使用

| 操作 | 入口 |
|---|---|
| 语言 | 更多 > 外观与语言 > 语言 |
| 捕获过滤 | 更多 > 捕获设置 > 捕获过滤 |
| TCP 分析 | 分析 > TCP 会话 > 流数据 |
| 应用层消息 | 分析 > 应用分析 |
| TLS 密钥 | 更多 > TLS 密钥日志 |
| 录制 | 更多 > 捕获设置 > 录制设置，录制到磁盘 |
| 显示表达式 | 筛选工具条 > 显示表达式 |
| 打开 / 保存 | Ctrl+O / Ctrl+S |
| 应用地址条件 | Ctrl+Enter |

## 编译

C++20, MSVC 2022 x64, Qt 6.8.3, CMake 3.24+, Npcap SDK 1.16。脚本构建 OpenSSL 3.5.9 和 nghttp2 1.70.0。

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
