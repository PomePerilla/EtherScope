# EtherScope v1.9.0

[English](README.md) | [简体中文](README.zh-CN.md) | 繁體中文

Windows x64 網路協定分析器。

- Ethernet、VLAN、IPv4、IPv6、ICMP、ICMPv6、ARP、TCP、UDP。
- BPF 擷取篩選、位址與協定顯示篩選、PCAP 檔案。
- 封包清單、欄位與原始位元組連動，背景匯出。
- TCP 會話、交握、串流重組與關聯封包定位。
- English、简体中文、繁體中文。

## 下載

[EtherScope v1.9.0](https://github.com/PomePerilla/EtherScope/releases/tag/v1.9.0)

| 檔案 | 用途 |
|---|---|
| `EtherScope-1.9.0-windows-x64.zip` | 安裝後使用 |
| `EtherScope-1.9.0-sourcecode.zip` | 編譯後使用 |

1. 安裝 [Npcap 1.89](https://npcap.com/dist/npcap-1.89.exe)。
2. 解壓縮程式套件，執行安裝程式。
3. 開啟 EtherScope，選擇網路介面，開始。

## 使用

| 操作 | 入口 |
|---|---|
| 語言 | 更多 > 語言 |
| 擷取篩選 | 更多 > 擷取篩選 |
| TCP 分析 | 更多 > TCP 會話 > 串流資料 |
| 開啟 / 儲存 | Ctrl+O / Ctrl+S |
| 套用位址條件 | Ctrl+Enter |

## 編譯

C++20, MSVC 2022 x64, Qt 6.8.3, CMake 3.24+, Npcap SDK 1.16.

```powershell
.\scripts\build.ps1 -Clean -Test -QtRoot 'C:\Qt\6.8.3\msvc2022_64' -NpcapSdkRoot 'C:\SDK\npcap-sdk-1.16'
```

## 測試

```powershell
python tests/check_translations.py
```

建置指令執行核心與介面測試。GitHub Actions 執行 ASan、UBSan、靜態檢查與模糊測試。

## 授權

[MIT](LICENSE)。[第三方元件](THIRD_PARTY_NOTICES.md)。
