# Aegis Chain 当前状态（唯一状态真值）

> 状态日期：2026-09-05
> 当前协作基线：`main`（包含 v0.1 后续 P0/P1 与第三方动态实验）；最新不可变比赛标签为 `v0.1`，其历史发布范围见 [`RELEASE_V0.1.md`](RELEASE_V0.1.md)。
> 当前工程阶段：静态基线保持可复核，论文驱动的 OpenClaw Skill P0/P1 增强已完成本机工程验收。P0 覆盖语义操纵、声明—实现一致性、本地 Qwen 复核和 OpenClaw 控制面；P1 覆盖纯指令、Python、Node.js、Shell 与三轮 Docker 隔离试运行。P2 已完成 6 个官方真实脚本及 30 个受控风险孪生的第三方动态配对主实验。第二台洁净 Windows/真实 VM、eBPF/ETW 旁证和生产控制面继续延期且不阻断比赛交付。
> 状态优先级：本文件高于 README 中的摘要和全部日期化阶段报告；发生冲突时以本文件及对应冻结证据为准。

## 1. 一句话结论

Aegis Chain 已作为 OpenClaw `2026.7.1-2` 的后台安全引擎接入：唯一“Aegis 安全中心”默认展示真实总览，并提供准入、报告、审计、规则和 MCP 五个内部标签。准入可上传 ZIP 或本地文件夹，执行静态审计与 Docker 隔离试运行，只有 `ALLOW` 才能安装；Skill/Plugin 原生安装仍自动准入，配置型 MCP 提交前准入。竞赛正式版 `v0.1` 的现场演示与材料提交状态 **READY**；第二台洁净 Windows 证据、生产身份权限与外部审计仍未完成，生产发布保持 **NO-GO**。

## 2. 当前可复核能力

| 能力 | 当前结论 | 关键边界 |
| --- | --- | --- |
| Skill 静态审计 | 可用；Cisco + Aegis 规则/流分析进入统一 Finding 和四态门禁 | 静态无告警不等于绝对安全 |
| MCP 静态审计 | 可用；Tool/Prompt/Resource 与可选依赖清单统一审查 | 当前上传协议是离线 JSON，不连接未知远端服务 |
| Python 依赖审计 | 可用；`pip-audit` + 完整性规则 + CycloneDX 导出 | 当前 SBOM 主要覆盖任务声明依赖，不代表项目自身发布 SBOM 已完成 |
| 准入决策 | `ALLOW / REVIEW / BLOCK / UNKNOWN`；扫描异常失败闭锁 | 默认静态模式不变；显式 `required` 动态模式只允许维持或提高风险 |
| OpenClaw 最终集成 | 单一“Aegis 安全中心”入口；默认真实总览与五功能标签；ZIP/文件夹 Skill 正式上传；扫描资格绑定 SHA-256；`ALLOW` 后安装；同名确认事务替换；Skill/目录 Plugin 自动准入；配置型 MCP 事务提交复核；PDF、规则即时生效、61条审计链通过 | 稳定版不支持 warn；单文件/归档 Plugin 未专项验收；审计尚未外送 SIEM/WORM |
| 管理员受控动态机制 | 可用；固定良性 fixture、MCP 协议/Marker/遥测和 Skill 运行时闭包 | 管理员 fixture API 仍不接受用户代码、路径或命令 |
| Skill 安装前动态沙箱 | 纯指令/Python/Node/Shell 路由；三轮输入；6/6 工程验收、6/6 正式端到端及 36 包第三方配对主实验通过 | 只运行静态预筛后支持的入口；语言钩子可绕过，Docker 不等于虚拟机或内核级完整监控 |
| OpenClaw Skill P0 静态语义 | 自然语言与能力一致性规则、本地 Qwen 复核和 OpenClaw 控制面规则已接入正式准入 | 机制配对集不是外部准确率基准；大模型不能单独形成 BLOCK |
| P2 权威生态评测 | MaliciousSkillBench 官方 Source-Disjoint test 全量1,384条已完成 Cisco/P0/P1 三版本真实批量评测 | 当前 P0 恶意不放行召回15.6%、良性允许率74.1%；结果表明仍需在独立 train/validation 上补语义泛化与误报控制 |
| P2 真实第三方动态配对 | 6 个 Apache-2.0 官方原始 Skill + 30 个受控风险孪生完成 108 次容器脚本调用；动态风险规则召回30/30，原始脚本动态 ALLOW 6/6 | 已知恶意第三方 Skill 执行0；单调融合后原始包最终仅1 ALLOW、4 REVIEW、1 BLOCK，静态误报仍需改进 |
| 动态任务控制 | 单主机 SQLite 持久队列、全局单执行、FIFO、去重冷却、429 和重启恢复 | 不等价于多实例消息队列或高可用 worker |
| 项目自身供应链 | 共享运行时/前端精确锁定，自身 SBOM、许可、漏洞、Secret 与仓库卫生门可复现 | 漏洞结论是 2026-08-25 的时间截面 |
| Windows 一键部署 | 当前主机安装/修复全流程通过：固定版本、配置备份/回滚、策略自举、插件安装、Gateway 重启、统一安全中心六视图探活和24项动态预检0警告 | 尚未取得第二台洁净 Windows 或真实 VM 的完整通过证据；首次准备扫描运行时需要联网且耗时较长 |

## 3. 最新冻结验证

- M11 正式上传准入：ZIP 安全 Skill 扫描/安装、文件夹安全 Skill 扫描/同名确认更新、恶意文件夹静态阻断均由真实 Edge 操作 OpenClaw 页面通过；恶意样本动态执行 0、安装按钮禁用。
- M12/v0.1 统一安全中心：插件只注册一个“Aegis 安全中心”侧边栏描述符；默认总览与五功能同层导航真实 Edge 验收通过，控制台错误 0；v0.1 采用适配 2K 的浅色政企控制台，原始执行终端保持深色并展示真实日志。
- 当前真实审计：M11 序号52–58证据保持；后续安全 Skill、同名更新与恶意阻断记录累计至65条；65条 SHA-256 审计链有效，允许35条、阻断30条。
- 当前回归：后端 `507 passed, 1 skipped`，OpenClaw 安全中心与上传边界 Node 测试 `19 passed`，前端 `10 passed`、生产构建通过。
- 最终 PDF：`output/pdf/Aegis-OpenClaw-Final-Acceptance.pdf`，序号39，A4单页，90,040字节，渲染检查通过。
- Docker 4.86.0 Windows AF_UNIX 遗留故障已按可恢复方式修复；Engine 29.7.2/API 1.55 和固定镜像摘要通过，恢复逻辑已纳入一键安装器。

- P0-2 动态队列专项：`14 passed`；最大并发 running 为 1，FIFO 违反、重复新增任务和永久中间态均为 0。
- P0-4 自身供应链门：12/12 gate 通过；共享环境 126 个 Python 包、Windows x64 已安装 26 个 Node 包和 pnpm 锁内 50 个组件完成核对；已知漏洞 0、已验证凭据泄露 0、许可未知/越界 0、锁不匹配 0。
- Cisco 兼容冒烟：Skill 固定集完成；MCP 内容 6 项中 safe 3/unsafe 3；已知漏洞 fixture 检出 24 项 HIGH，安全 fixture 0 项；内部 pip-audit 失败会被复现脚本拒绝。
- P0-5 验收程序本机非正式烟雾：Skill、MCP、依赖和受控动态 4/4 链完成，导出 7/7；Docker 缺失返回明确 503；漏洞服务断网形成 `failed / UNKNOWN / SCAN_EXECUTION_FAILED`。
- P0-5 真实运行：三次均完成私有远端新克隆、VM 证明和负向 preflight，随后分别暴露日志可观测性、Windows Conda 解释器布局和 Conda `Library\bin` PATH 问题；失败证据逐次固化，第四次运行未执行，不能计作通过。
- P0-5 范围决策：2026-08-26 确认洁净 Windows VM 不是赛题明示交付物，故延期为可选工程增强，不再阻断比赛交付；临时 GitHub Deploy Key 已吊销，本地私钥、公钥和专用 `known_hosts` 已删除。
- M6-2 OpenClaw E2E：安全安装成功；恶意阻断、中风险兼容阻断和策略路径失败关闭；非预期工作区残留 0。
- M6-3 准入加固：Cisco Skill/MCP/依赖真实冒烟通过；完整 preflight ready；安全/恶意审计2行、哈希链有效。
- M6-4 Plugin/MCP：真实良性 Plugin 安装成功；npx运行时下载 Plugin 阻断且残留0；3行真实审计链有效。
- 静态最终补强：有依赖 Plugin 在缺少 Node 漏洞证据时强制 REVIEW；加入 P0 语义与能力一致性后，Aegis 静态规则注册表138条完整。
- M10 OpenClaw Skill P0/P1：开发集20/20；首次回归观测14/16并修复两处缺陷，修复后同集16/16，新鲜回归v2为12/12。真实 Python/Node/Shell 动态验收6/6、容器安全门和三轮证明全部通过、残留0；正式 OpenClaw 端到端6/6。报告：`demo_web/docs/M10_OPENCLAW_SKILL_P0_P1_IMPLEMENTATION_ACCEPTANCE_REPORT.md`。
- P2 权威主实验：MaliciousSkillBench 固定提交的 Source-Disjoint test 全量1,384条；Cisco-only 恶意不放行召回3.2%/良性允许率94.9%，Cisco+P0为15.6%/74.1%，文本快照集上P1决策增量0、容器执行0。该结果已冻结且不用于直接调参；结论与下一路线：`demo_web/docs/M12_MALICIOUSSKILLBENCH_1384_RESULT_AND_P2_ROUTE.md`。
- P2 真实第三方动态主实验：从 OpenAI 官方 Skills 选取5个原型、Anthropic 官方 Skills 选取1个原型，形成6个原始包和30个受控风险孪生；36包×3轮共108次容器调用。动态预期规则召回30/30、风险非放行30/30、原始脚本动态 ALLOW 6/6，三轮、安全门、清理、输入树不变均100%，残留容器0；动态补齐4个静态 ALLOW 漏检，并将14个静态 REVIEW 升级为 BLOCK。单调融合后原始包为1 ALLOW、4 REVIEW、1 BLOCK，因此静态可用性仍是下一瓶颈。合同与结论：`demo_web/docs/M13_REAL_THIRD_PARTY_SKILL_DYNAMIC_EXPERIMENT_CONTRACT.md`、`demo_web/docs/M14_REAL_THIRD_PARTY_SKILL_DYNAMIC_RESULT_AND_GAP.md`。
- M7 阶段历史完整回归：`422 passed, 1 skipped`；该数字仅用于说明当时基线，当前结果以本文前述 `507 passed, 1 skipped` 为准。
- 前端 API 测试：`10 passed`。
- 前端生产构建：通过。
- P0-2 证据：`demo_web/artifacts/experiment/2026-08-24-dynamic-queue-recovery-dev-v1/`。
- P0-1 证据：`demo_web/artifacts/experiment/2026-08-24-portable-startup-dev-v1/`。
- P0-4 证据：`demo_web/artifacts/experiment/2026-08-24-project-supply-chain-hygiene-dev-v1/`。
- M3 600 条密封回归结论仍为 `supported_with_tradeoff`，未因工程改造重新调规则。
- M6-4 证据：`demo_web/artifacts/experiment/2026-08-26-openclaw-plugin-mcp-admission-v1/`；最终评委复核：`demo_web/docs/STATIC_AUDIT_FINAL_JUDGE_REVIEW_2026-08-26.md`。
- M7 动态沙箱开发证据：`demo_web/artifacts/experiment/2026-08-27-skill-dynamic-sandbox-dev-v1/`；该开发时间截面的结论为逻辑链 `supported`、真实 Docker/Falco 运行 `inconclusive`。
- M7 真实 Docker 重复验收：`demo_web/artifacts/experiment/2026-08-27-skill-dynamic-sandbox-real-v2/`；5 类场景×3轮共 15/15 决策正确，动态 BLOCK 9、REVIEW 3；良性误报、危险漏报、遥测缺失、清理失败和容器残留均为 0。默认 Python 后端结论更新为 `supported_on_self_built_real_docker_fixtures`，Falco 仍为可选且 `inconclusive`。
- M7 20 样本稳定性回归：v1 按原预期 60/60 通过，但运行后审查发现 `os.system()` 标签偏宽松；原始结果保留。v2 将其提升为 `AEGIS_DYNAMIC_SHELL_SPAWN / CRITICAL / BLOCK` 后重新执行 20 个样本、8 类行为、3 轮共 60 次，决策与必需规则均 60/60，ALLOW 12、REVIEW 12、BLOCK 36；良性误报、危险漏报、复核错配、跨轮不稳定、遥测缺失、清理失败和容器残留均为 0。证据：`demo_web/artifacts/experiment/2026-08-27-skill-dynamic-regression20-v2/`。
- M7 OpenClaw 动态 E2E：v1 因隔离 profile 缺少 Docker context 失败并保留证据；v2 用单一环境修复后 3/3 通过。安全 Skill 真实安装，静态 ALLOW 的 Shell Skill 被 `AEGIS_DYNAMIC_SHELL_SPAWN` 阻断，配置异常失败关闭；审计链有效，输入变化、阻断目录残留、用户默认 workspace 污染和容器残留均为 0。证据：`demo_web/artifacts/experiment/2026-08-27-openclaw-skill-dynamic-e2e-v2/`。
- M9 OpenClaw Web 控制台准入：通过官方插件 Tab 与 Gateway HTTP Route 增加“Aegis 准入”页；固定 `case_00906` 与 `case_01084`，分别实现一键真实安装放行和安装前阻断。页面底部实时展示原始子进程日志、6 阶段进度和 8 项证据，不是前端模拟动画。正常样本 `ALLOW + Docker 动态清洁 + 安装成功`，恶意样本 `BLOCK + 动态执行 0 次 + 无安装目录`，两者审计链均有效。设计与验收：`demo_web/docs/M9_OPENCLAW_CONTROL_UI_ADMISSION_DESIGN.md`。
- M11 已取代 M9 固定演示页：准入页接受真实 ZIP/文件夹上传，实施 50 MB ZIP、200 MB 解压/文件夹、5,000 文件上限和安全解包；扫描后资格绑定内容哈希，安装时复核并由 OpenClaw 原生策略二次扫描。同名更新使用页面内明确确认与失败恢复。正式设计与验收：`demo_web/docs/M11_OPENCLAW_FORMAL_SKILL_UPLOAD_ADMISSION.md`。
- M12 将五个 OpenClaw 侧边栏入口合并为唯一“Aegis 安全中心”，默认真实总览，保留五功能同层导航和旧 HTTP 路由跳转，且未放宽 CSP。正式发布说明：`demo_web/docs/M12_OPENCLAW_UNIFIED_SECURITY_CENTER_RELEASE.md`。

## 4. M5 完成度

| 优先级 | 工作项 | 状态 | 下一验收门 |
| --- | --- | --- | --- |
| P0-1 | 可移植启动与运行时重建 | 已完成 | 当前主机交付演练和运行说明复核 |
| P0-2 | 动态互斥、队列、去重、恢复 | 已完成 | P2-2 再做外部 worker/DB |
| P0-3 | 当前状态单一真值 | 已完成 | 文档契约测试持续防漂移 |
| P0-4 | 项目自身供应链卫生 | 已完成 | 依赖/运行时/许可/SBOM/Secret 门持续执行 |
| P0-5 | 真实 Windows VM 发布门 | **延期；三次失败证据保留；不阻断比赛交付** | 仅在比赛核心材料完成且仍有余量时重启；重启须重新创建一次性只读认证并使用全新工作区 |
| P1 | OpenClaw Skill 多运行时动态试点 | **已完成本机工程验收及第三方配对主实验** | 后续再做独立内核遥测、静态误报治理与生产控制面 |
| P2 | 生产化控制面 | 未完成 | 非本次比赛交付前置；作为生产化路线与明确限制记录 |

详细验收合同与实施顺序见 `demo_web/docs/M5_ENGINEERING_EXECUTION_PLAN.md`，勾选进度见 `demo_web/CHECKLIST.md`。

## 5. 明确不主张

- 不主张已达到生产可用或可直接接入真实政企生产网。
- 不主张 Docker/WSL2 等同于虚拟机级恶意代码隔离。
- 不主张容器试运行可以安全覆盖任意第三方 Skill、MCP Server、未知镜像或已知恶意数据集样本；当前只在固定镜像和严格门禁中运行经人工/静态预筛、受支持的 Skill 脚本入口。
- 不主张受控 fixture 的通过结果能证明某个外部组件安全。
- 不主张当前身份令牌、SQLite 和单进程调度已经满足多租户、高可用与合规审计。
- 不主张三次 P0-5 失败运行或已安装 VM 等价于洁净 Windows 发布门通过。
- 不主张稳定版兼容阻断等价于可确认 warn；不主张单文件/归档 Plugin、未知在线 MCP 或任意第三方代码已经安全通过。
- 不主张本地 SQLite 哈希链等价于外部 WORM、可信时间戳或企业 SIEM；不主张企业认证代理与凭据托管已完成。
- 不主张 Plugin 单文件/归档、安装后 Plugin 运行时隔离或 Plugin 权威数据集评测已经完成。
- 不主张当前已完成 Falco/eBPF 系统调用级审计；不主张仅靠 Python 审计钩子即可对抗主动绕过。
- 不主张旧阶段报告中的测试总数、下一步或“最终”字样代表当前状态。

## 6. 文档解释规则

1. `CURRENT_STATUS.md`：唯一当前状态、发布判断和下一工程节点。
2. `QUICKSTART.md`、`SECURITY.md`、`demo_web/docs/API_V1_CONTRACT.md`：当前操作、安全和接口契约。
3. `demo_web/docs/M5_ENGINEERING_EXECUTION_PLAN.md`、`demo_web/PLAN.md`、`demo_web/CHECKLIST.md`：当前执行细节。
4. `RELEASE_V0.1.md`：当前正式版范围、安装入口、验证摘要和 GitHub Release 说明。
5. `M1`–`M4`、日期化报告、`REPRODUCTION_REPORT.md`、旧评委审查：历史时间截面，仅证明当时实验，不覆盖本文件。

每次里程碑提交必须同步本文件中的基线、测试数、完成度和下一项；若尚未同步，不得把新里程碑称为已冻结。
