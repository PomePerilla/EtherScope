# 第三方组件

EtherScope 源码使用 [MIT](LICENSE) 许可证。

| 组件 | 版本 | 用途 | 许可 |
|---|---|---|---|
| Qt Core / Gui / Widgets | 6.8.3 | 动态链接 | [LGPL v3](https://doc.qt.io/qt-6.8/licensing.html) |
| Qt Test | 6.8.3 | 自动测试 | [LGPL v3](https://doc.qt.io/qt-6.8/qttest-index.html#licenses-and-attributions) |
| Npcap SDK | 1.16 | 构建头文件 | SDK 各文件所附许可 |
| Npcap | 1.89 | 实时抓包 | [Npcap EULA](https://github.com/nmap/npcap/blob/master/LICENSE) |
| MSVC 运行库 | v143 x64 | C++ 运行依赖 | Microsoft 随附许可 |
| Inno Setup | 6.7.3 | 安装包构建 | [Inno Setup License](https://jrsoftware.org/files/is/license.txt) |

## Qt

- [LGPL v3 许可文本](docs/licenses/LGPL-3.0.txt)
- [GPL v3 许可文本](docs/licenses/GPL-3.0.txt)
- [Qt Base 6.8.3 源码](https://download.qt.io/archive/qt/6.8/6.8.3/submodules/qtbase-everywhere-src-6.8.3.tar.xz)
- 安装包内的 Qt 组件清单位于 `licenses/Qt-6.8.3.spdx.json`。

## Npcap

Npcap 使用独立许可，不属于 EtherScope 的 MIT 授权范围。

- [驱动下载](https://npcap.com/#download)
- [SDK 下载](https://npcap.com/dist/npcap-sdk-1.16.zip)
- 对外分发驱动安装器须取得 Nmap 的书面授权。
