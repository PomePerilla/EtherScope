---
name: workbench-ui-pipeline
description: Build or refactor compact data-workspace interfaces using reusable visual tokens, action/filter/detail organization, source-bound interaction, and visual QA. Use for cross-project workbench UI design and implementation, including Qt Widgets and web frontends; adapt the layout to the product's primary task.
---

# 工作台界面管线

把业务任务落实为可运行界面。默认视觉来自 EtherScope 的黄黑工作台，品牌色与布局可按项目覆盖。沿用目标项目的技术栈、业务模型及已授权范围。

## 先识别项目

阅读目标项目的入口、主题、组件、路由／窗口、状态管理和相关测试。确认主要用户任务、数据身份、更新方式和可用屏幕尺寸。已有品牌优先；用户要求沿用本风格时使用 `assets/tokens.json` 的默认值。

在目标项目记录一份简短的界面契约，使用 [project-contract.json](assets/project-contract.json)。填写主任务、操作层级、适用布局、状态和检查范围。信息可从代码得到时直接补齐；只询问会改变业务流程的缺失信息，继续完成无依赖工作。

## 选择组织方式

阅读 [布局与交互](references/layout-and-state.md)，按任务选择：

- 列表 → 选择 → 详情：使用主列表与检查器，可增加原始内容区。
- 导航 → 编辑／查看：使用导航与内容区，详情按需打开。
- 连续监控 → 排查：保留工作区，分析与诊断按需停靠或浮动。

把全局操作、来源／视图、筛选、有效条件、内容和状态分层。窄屏根据实际控件宽度换行；优先保留主任务操作。具体窗格数量、默认尺寸和快捷键由项目决定。

## 生成视觉与接入

阅读 [视觉系统](references/visual-system.md)。使用语义 token 统一颜色、字体、密度、间距和状态；主操作、焦点、选中以及状态标记分别有明确职责。

```text
python <skill>/scripts/build.py --config <project-contract.json> --output <new-output-directory>
```

生成 `tokens.css`、`components.css`、离线样板、Qt 调色板头文件和两套 QSS。脚本拒绝写入已有目录。配置与生成物一起保留，后续通过新目录比较差异再合入。

按当前技术栈只阅读 [接入适配](references/adapters.md) 的相应部分：

- Web：将 token 接到现有 CSS／组件主题，逐步替换硬编码。HTML 样板用于验证组织方式和交互。
- Qt Widgets：使用调色板与 QSS 适配；需要自动换行时使用随包 `FlowLayout`。Qt 样板保留原生外框，按项目要求实现无边框窗口并单独验证系统行为。
- 其他框架：从同一 token 和界面契约映射原生控件，保留键盘、字体和缩放行为。

样板中的数据、图标与状态是演示素材。替换成目标项目内容；品牌图标由项目提供。包内不携带 EtherScope 商标或捕获／分析服务。

## 统一交互

动作的启用条件共享一个来源，菜单和工具栏复用；图标按钮补齐提示和无障碍名称。

持续更新列表使用稳定身份，保存阅读锚点；来源和代数变化后明确失效。右键操作冻结打开时目标；复制使用当时值，变更动作执行前验证身份。把暂存草稿、已应用筛选、查找和阅读历史分开。详见 [布局与交互](references/layout-and-state.md)。

文案采用“当前状态＋操作”；字段说明采用“用途＋当前值”。只呈现读数、条件、失败原因和下一步。沿用目标项目语言范围。

## 验证与交付

使用 [验收方法](references/verification.md) 选择与本次改动相关的状态、窗口、语言和缩放组合，检查整套控件及辅助窗口。

```text
python <skill>/scripts/check.py --config <project-contract.json> --generated <output-directory>
python <skill>/scripts/self_test.py
```

脚本检查配置、配色对比度、生成一致性和写入边界。还需在实际框架中检查布局、交互、任务关闭及性能；记录执行环境、截图和未执行项。包的自测结果不能代替目标项目验收。

可用 Chromium／Edge 验证离线 Web 样板：`python <skill>/scripts/verify_web.py --browser <executable> --generated <output-directory> --output <evidence-directory>`。该工具记录 11 条交互断言和参考尺寸截图。Qt 样板使用 `workbench_sample --smoke <evidence-directory> -platform offscreen`；原生窗口与实际 DPI 另测。

交付配置、接入后的代码、可启动入口、对比截图和验证记录。打包、发布及安装动作遵循本次用户授权。

## 包的维护

本目录是可独立复制的技能包。通过 `scripts/install.py --destination <skills-directory>` 安装到本机；已有同名目录会停止，更新时先比较。设计来源和维护范围见 [来源与范围](references/provenance.md)。
