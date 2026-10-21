# EtherScope v1.7.0

Windows x64 协议分析器。支持实时抓包、IPv4 / IPv6 解析、BPF 捕获过滤、MAC / IP 显示过滤和 PCAP 读写。

按需字段解析、IPv4 / ICMP 校验和、ICMP 类型筛选和 TCP 会话分析。

## 运行

1. 下载并安装 [Npcap 1.89](https://npcap.com/dist/npcap-1.89.exe)。
2. 解压程序包，运行其中的安装器。
3. 打开 EtherScope。

## 构建环境

| 组件 | 版本 | 用途 |
|---|---|---|
| C++ | 20 | 编译 |
| MSVC | 2022 x64 | 编译 |
| Qt Core / Gui / Widgets / Test | 6.8.3 msvc2022_64 | 界面与测试 |
| CMake | 3.24+ | 构建 |
| [Npcap SDK](https://npcap.com/dist/npcap-sdk-1.16.zip) | 1.16 | 抓包接口 |
| Inno Setup | 6.7.3 | 安装包构建 |

## 编译

```powershell
.\scripts\build.ps1 -Clean -Test -QtRoot 'C:\Qt\6.8.3\msvc2022_64' -NpcapSdkRoot 'C:\SDK\npcap-sdk-1.16'
```

## 核心测试

在 MSVC x64 开发者终端中运行：

```powershell
cmake -S . -B build/core -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release -DETHERSCOPE_BUILD_GUI=OFF
cmake --build build/core
ctest --test-dir build/core --output-on-failure
```

## 核心模糊测试

```sh
cmake -S . -B build/fuzz -DETHERSCOPE_BUILD_GUI=OFF -DETHERSCOPE_BUILD_FUZZERS=ON -DCMAKE_CXX_COMPILER=clang++-18
cmake --build build/fuzz
build/fuzz/make_fuzz_corpus build/corpus
build/fuzz/packet_fuzzer build/corpus -max_len=65540 -max_total_time=120
```

## 打包

```powershell
.\scripts\package-source.ps1
.\scripts\package-program.ps1 -QtRoot 'C:\Qt\6.8.3\msvc2022_64' -MsvcRuntimeRoot 'C:\VC143.CRT' -InnoCompiler 'C:\InnoSetup\ISCC.exe'
```

## 文件

| 项目 | 路径 |
|---|---|
| 程序 | `build/msvc-release/EtherScope.exe` |
| 源码 | `src` |
| 测试 | `tests` |
| 构造样本 | `samples` |

## 发行

Windows x64

| 附件 | 类型 | 使用方式 |
|---|---|---|
| `EtherScope-1.7.0-windows-x64.zip` | 程序包 | 安装后使用 |
| `EtherScope-1.7.0-sourcecode.zip` | 源码包 | 编译后使用 |

## 许可

[MIT](LICENSE)。第三方组件见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
