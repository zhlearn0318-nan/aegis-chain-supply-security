# Aegis Chain 当前状态（唯一状态真值）

> 状态日期：2026-08-27
> 最近推送工程基线：`6526843`（`dynamic-audit-v1`）；本次范围决策由包含本文件的提交承载。
> 当前工程阶段：静态审计比赛版本保持冻结；在 `skill-dynamic-sandbox-v1` 分支开发 Skill 安装前 Docker 隔离试运行。确定性逻辑与准入联动已通过回归，真实 Docker/Falco 运行因本次会话中 Linux Engine 未启动而尚未验收；P0-5 真实 VM 验收继续延期且不阻断比赛交付。
> 状态优先级：本文件高于 README 中的摘要和全部日期化阶段报告；发生冲突时以本文件及对应冻结证据为准。

## 1. 一句话结论

Aegis Chain 已被真实 OpenClaw 稳定版调用，并完成 Skill 与目录型原生 Plugin 静态安装准入；新增 Skill 安装前动态策略能够保证“静态 BLOCK 不执行、动态高危升级 BLOCK、动态失败不 ALLOW”，但真实第三方 Skill 容器运行和 Falco eBPF 旁证尚未验收，生产发布决策保持 **NO-GO**。

## 2. 当前可复核能力

| 能力 | 当前结论 | 关键边界 |
| --- | --- | --- |
| Skill 静态审计 | 可用；Cisco + Aegis 规则/流分析进入统一 Finding 和四态门禁 | 静态无告警不等于绝对安全 |
| MCP 静态审计 | 可用；Tool/Prompt/Resource 与可选依赖清单统一审查 | 当前上传协议是离线 JSON，不连接未知远端服务 |
| Python 依赖审计 | 可用；`pip-audit` + 完整性规则 + CycloneDX 导出 | 当前 SBOM 主要覆盖任务声明依赖，不代表项目自身发布 SBOM 已完成 |
| 准入决策 | `ALLOW / REVIEW / BLOCK / UNKNOWN`；扫描异常失败闭锁 | 默认静态模式不变；显式 `required` 动态模式只允许维持或提高风险 |
| OpenClaw 安装策略 | Skill 与目录型原生 Plugin 真实安装成功；恶意 Skill、运行时下载 Plugin 和异常均阻断；随包 MCP manifest、环境白名单、审计链、preflight 已通过 | 稳定版不支持 warn；配置型 MCP、单文件/归档 Plugin 未接入；审计尚未外送 SIEM/WORM |
| 受控动态机制 | 可用；固定良性 fixture、MCP 协议/Marker/遥测和 Skill 运行时闭包 | 不接受用户代码、路径、命令，不执行第三方数据集样本 |
| Skill 安装前动态沙箱 | 开发中；Python 入口发现、Docker 安全合同、行为规则、Falco JSON 适配和 OpenClaw 单调融合已实现 | 本轮只有测试证据；Docker Linux Engine/Falco 未完成真实运行，不宣称可安全执行任意第三方 Skill |
| 动态任务控制 | 单主机 SQLite 持久队列、全局单执行、FIFO、去重冷却、429 和重启恢复 | 不等价于多实例消息队列或高可用 worker |
| 项目自身供应链 | 共享运行时/前端精确锁定，自身 SBOM、许可、漏洞、Secret 与仓库卫生门可复现 | 漏洞结论是 2026-08-25 的时间截面 |
| 可移植启动 | 当前主机和模拟异用户环境通过；真实 VirtualBox Windows guest、固定工具链和四链 E2E 验证程序均已建立 | 三次远端新克隆均在运行时重建阶段失败；失败推动了日志、Conda 布局和 PATH 三类修复，但不构成洁净 VM 通过证据 |

## 3. 最新冻结验证

- P0-2 动态队列专项：`14 passed`；最大并发 running 为 1，FIFO 违反、重复新增任务和永久中间态均为 0。
- P0-4 自身供应链门：12/12 gate 通过；共享环境 126 个 Python 包、Windows x64 已安装 26 个 Node 包和 pnpm 锁内 50 个组件完成核对；已知漏洞 0、已验证凭据泄露 0、许可未知/越界 0、锁不匹配 0。
- Cisco 兼容冒烟：Skill 固定集完成；MCP 内容 6 项中 safe 3/unsafe 3；已知漏洞 fixture 检出 24 项 HIGH，安全 fixture 0 项；内部 pip-audit 失败会被复现脚本拒绝。
- P0-5 验收程序本机非正式烟雾：Skill、MCP、依赖和受控动态 4/4 链完成，导出 7/7；Docker 缺失返回明确 503；漏洞服务断网形成 `failed / UNKNOWN / SCAN_EXECUTION_FAILED`。
- P0-5 真实运行：三次均完成私有远端新克隆、VM 证明和负向 preflight，随后分别暴露日志可观测性、Windows Conda 解释器布局和 Conda `Library\bin` PATH 问题；失败证据逐次固化，第四次运行未执行，不能计作通过。
- P0-5 范围决策：2026-08-26 确认洁净 Windows VM 不是赛题明示交付物，故延期为可选工程增强，不再阻断比赛交付；临时 GitHub Deploy Key 已吊销，本地私钥、公钥和专用 `known_hosts` 已删除。
- M6-2 OpenClaw E2E：安全安装成功；恶意阻断、中风险兼容阻断和策略路径失败关闭；非预期工作区残留 0。
- M6-3 准入加固：Cisco Skill/MCP/依赖真实冒烟通过；完整 preflight ready；安全/恶意审计2行、哈希链有效。
- M6-4 Plugin/MCP：真实良性 Plugin 安装成功；npx运行时下载 Plugin 阻断且残留0；3行真实审计链有效。
- 静态最终补强：有依赖 Plugin 在缺少 Node 漏洞证据时强制 REVIEW；Aegis 静态规则注册表125条完整。
- 后端完整回归：`417 passed, 1 skipped`；跳过项仅为当前 Windows 测试账户无符号链接创建权限。
- 前端 API 测试：`10 passed`。
- 前端生产构建：通过。
- P0-2 证据：`demo_web/artifacts/experiment/2026-08-24-dynamic-queue-recovery-dev-v1/`。
- P0-1 证据：`demo_web/artifacts/experiment/2026-08-24-portable-startup-dev-v1/`。
- P0-4 证据：`demo_web/artifacts/experiment/2026-08-24-project-supply-chain-hygiene-dev-v1/`。
- M3 600 条密封回归结论仍为 `supported_with_tradeoff`，未因工程改造重新调规则。
- M6-4 证据：`demo_web/artifacts/experiment/2026-08-26-openclaw-plugin-mcp-admission-v1/`；最终评委复核：`demo_web/docs/STATIC_AUDIT_FINAL_JUDGE_REVIEW_2026-08-26.md`。
- M7 动态沙箱开发证据：`demo_web/artifacts/experiment/2026-08-27-skill-dynamic-sandbox-dev-v1/`；当前结论为逻辑链 `supported`、真实 Docker/Falco 运行 `inconclusive`。

## 4. M5 完成度

| 优先级 | 工作项 | 状态 | 下一验收门 |
| --- | --- | --- | --- |
| P0-1 | 可移植启动与运行时重建 | 已完成 | 当前主机交付演练和运行说明复核 |
| P0-2 | 动态互斥、队列、去重、恢复 | 已完成 | P2-2 再做外部 worker/DB |
| P0-3 | 当前状态单一真值 | 已完成 | 文档契约测试持续防漂移 |
| P0-4 | 项目自身供应链卫生 | 已完成 | 依赖/运行时/许可/SBOM/Secret 门持续执行 |
| P0-5 | 真实 Windows VM 发布门 | **延期；三次失败证据保留；不阻断比赛交付** | 仅在比赛核心材料完成且仍有余量时重启；重启须重新创建一次性只读认证并使用全新工作区 |
| P1 | 受控试点工程能力 | 未完成 | 只优先实施直接提升实际效果、复现性和演示稳定性的项目 |
| P2 | 生产化控制面 | 未完成 | 非本次比赛交付前置；作为生产化路线与明确限制记录 |

详细验收合同与实施顺序见 `demo_web/docs/M5_ENGINEERING_EXECUTION_PLAN.md`，勾选进度见 `demo_web/CHECKLIST.md`。

## 5. 明确不主张

- 不主张已达到生产可用或可直接接入真实政企生产网。
- 不主张 Docker/WSL2 等同于虚拟机级恶意代码隔离。
- 不主张可安全执行第三方 Skill、MCP Server、未知镜像或数据集恶意样本。
- 不主张受控 fixture 的通过结果能证明某个外部组件安全。
- 不主张当前身份令牌、SQLite 和单进程调度已经满足多租户、高可用与合规审计。
- 不主张三次 P0-5 失败运行或已安装 VM 等价于洁净 Windows 发布门通过。
- 不主张稳定版兼容阻断等价于可确认 warn；不主张 Beta `doctor --deep` 安装策略项已全绿或插件/MCP 准入已经通过。
- 不主张本地 SQLite 哈希链等价于外部 WORM、可信时间戳或企业 SIEM；不主张企业认证代理与凭据托管已完成。
- 不主张配置型 OpenClaw MCP 写入、Plugin 单文件/归档、安装后运行时隔离或 Plugin 权威数据集评测已经完成。
- 不主张当前已完成 Falco/eBPF 系统调用级审计；不主张仅靠 Python 审计钩子即可对抗主动绕过。
- 不主张旧阶段报告中的测试总数、下一步或“最终”字样代表当前状态。

## 6. 文档解释规则

1. `CURRENT_STATUS.md`：唯一当前状态、发布判断和下一工程节点。
2. `QUICKSTART.md`、`SECURITY.md`、`demo_web/docs/API_V1_CONTRACT.md`：当前操作、安全和接口契约。
3. `demo_web/docs/M5_ENGINEERING_EXECUTION_PLAN.md`、`demo_web/PLAN.md`、`demo_web/CHECKLIST.md`：当前执行细节。
4. `M1`–`M4`、日期化报告、`REPRODUCTION_REPORT.md`、旧评委审查：历史时间截面，仅证明当时实验，不覆盖本文件。

每次里程碑提交必须同步本文件中的基线、测试数、完成度和下一项；若尚未同步，不得把新里程碑称为已冻结。
