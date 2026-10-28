# 接入适配

## 生成物

`scripts/build.py` 使用 Python 3 标准库，读取默认 token 和项目覆盖。输出目录必须是新目录；生成结果包括配置、合并 token、CSS、Qt 头文件／QSS、可交互 HTML 和 Qt 样板。

构建前运行 `scripts/check.py --config project-contract.json`，可提前发现颜色对比度与参数问题。构建后加 `--generated` 核对生成物是否与当前配置一致。

## Web

将 `tokens.css` 引入目标主题层，使用 `data-theme="dark|light"` 切换。`components.css` 中的 `.wb-*` 类覆盖工作区、动作条、条件、表格、检查器、诊断、焦点和状态。

样板是离线原生 HTML／CSS／JavaScript，无构建工具和网络资源。它演示主题、语言、筛选条件、字段联动、焦点查找和诊断，不连接业务后端。接入 React／Vue 等框架时保留其路由和状态管理，只迁移角色、布局和交互契约。

宽度适配由内容最小尺寸决定；Web 滚动容器设置 `min-width:0` 与 `min-height:0`，表格超宽时局部滚动。需要触屏时加大命中尺寸。持续更新列表使用业务键；虚拟化仅在数据量与测量需要时启用。

## Qt Widgets

生成物 `qt/workbench_style.h` 提供 `workbench::applyTheme(QApplication&, bool)`，读取同目录生成的 QSS；`workbench::dataFont()` 用于数据控件。`theme-dark.qss` 和 `theme-light.qss` 通过 `wbRole` 属性控制表面。

Qt 样板以列表／检查器演示同一套表面与动作状态。导航型或监控型项目按界面契约调整容器。生成器输出样板与主题；`actions`、`states` 和 `source_context` 是目标项目的接入约定，由实施时连接真实业务。样板不根据这些字段生成业务服务。

拷贝 `qt/` 后构建样板：

```text
cmake -S <generated>/qt -B <build> -DCMAKE_PREFIX_PATH=<Qt installation>
cmake --build <build>
```

模板依赖 Qt 6 Widgets，不依赖捕获、分析或 EtherScope 资源。样板默认原生窗口外框；若目标项目采用无边框，单独处理拖动、边缘命中、最大化工作区、最小化还原、任务栏图标、键盘与安全关闭，并在目标平台验证。Qt 6 的原生窗口能力使用目标项目当前支持的版本。

QSS 解决控件表面，表格行高、分隔条命中、模型身份及后台任务仍由组件代码设置。`FlowLayout` 用于实际宽度换行。菜单和工具条复用 QAction，动态属性变化后按需刷新样式；避免每次数据刷新重置全局主题。

## 其他框架

从生成的 `tokens.json` 映射到目标主题对象；按框架原生模式实现列表／检查器、浮层和焦点。不要为套用模板迁移技术栈。设计参数共用，窗口管理与任务生命周期由平台实现。
