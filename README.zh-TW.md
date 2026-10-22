# EtherScope v2.1.0

[English](README.md) | [简体中文](README.zh-CN.md) | 繁體中文

Windows x64 網路協定分析器。

- Ethernet、VLAN、IPv4、IPv6、ICMP、ICMPv6、ARP、TCP、UDP。
- BPF 擷取篩選、位址與協定顯示篩選、PCAP 和 PCAPNG 檔案。
- 封包清單、欄位與原始位元組連動，背景匯出。
- TCP 會話、交握、串流重組與應用層增量分析。
- DNS、HTTP/1.x、HTTP/2、TLS 中繼資料與金鑰記錄解密。
- PCAPNG 輪替錄製與顯示運算式。
- English、简体中文、繁體中文。
- 網卡與回環擷取。

## 下載

[EtherScope v2.1.0](https://github.com/PomePerilla/EtherScope/releases/tag/v2.1.0)

| 檔案 | 用途 |
|---|---|
| `EtherScope-2.1.0-windows-x64.zip` | 安裝後使用 |
| `EtherScope-2.1.0-sourcecode.zip` | 編譯後使用 |

1. 安裝 [Npcap 1.89](https://npcap.com/dist/npcap-1.89.exe)。
2. 解壓縮程式套件，執行安裝程式。
3. 開啟 EtherScope，選擇網路介面，開始。

## 使用

| 操作 | 入口 |
|---|---|
| 語言 | 更多 > 外觀與語言 > 語言 |
| 擷取篩選 | 更多 > 擷取設定 > 擷取篩選 |
| TCP 分析 | 分析 > TCP 會話 > 串流資料 |
| 應用層訊息 | 分析 > 應用分析 |
| TLS 金鑰 | 更多 > TLS 金鑰記錄 |
| 錄製 | 更多 > 擷取設定 > 錄製設定，錄製至磁碟 |
| 顯示運算式 | 篩選工具列 > 顯示運算式 |
| 開啟 / 儲存 | Ctrl+O / Ctrl+S |
| 套用位址條件 | Ctrl+Enter |

## 編譯

C++20, MSVC 2022 x64, Qt 6.8.3, CMake 3.24+, Npcap SDK 1.16。指令碼建置 OpenSSL 3.5.9 和 nghttp2 1.70.0。

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
