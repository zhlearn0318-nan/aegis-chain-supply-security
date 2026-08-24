# Aegis Chain 当前状态（唯一状态真值）

> 状态日期：2026-08-24  
> 最近冻结功能基线：`08562f6`（`dynamic-audit-v1`）；P0-4 状态同步由包含本文件的提交承载。
> 当前工程阶段：M5 工程收敛；P0-1 至 P0-4 已完成，下一项为 P0-5。
> 状态优先级：本文件高于 README 中的摘要和全部日期化阶段报告；发生冲突时以本文件及对应冻结证据为准。

## 1. 一句话结论

Aegis Chain 已是可在当前 Windows 主机运行和演示的供应链安全研究原型，具备 Skill、MCP、Python 依赖静态审计和仅面向自建哈希锁定样本的受控动态验证；它尚未通过洁净 Windows VM 发布门，也尚不具备生产政企平台所需的完整身份、租户、高可用和不可信代码强隔离，因此当前生产发布决策为 **NO-GO**。

## 2. 当前可复核能力

| 能力 | 当前结论 | 关键边界 |
| --- | --- | --- |
| Skill 静态审计 | 可用；Cisco + Aegis 规则/流分析进入统一 Finding 和四态门禁 | 静态无告警不等于绝对安全 |
| MCP 静态审计 | 可用；Tool/Prompt/Resource 与可选依赖清单统一审查 | 当前上传协议是离线 JSON，不连接未知远端服务 |
| Python 依赖审计 | 可用；`pip-audit` + 完整性规则 + CycloneDX 导出 | 当前 SBOM 主要覆盖任务声明依赖，不代表项目自身发布 SBOM 已完成 |
| 准入决策 | `ALLOW / REVIEW / BLOCK / UNKNOWN`；扫描异常失败闭锁 | 动态证据当前不改变最终决策 |
| 受控动态机制 | 可用；固定良性 fixture、MCP 协议/Marker/遥测和 Skill 运行时闭包 | 不接受用户代码、路径、命令，不执行第三方数据集样本 |
| 动态任务控制 | 单主机 SQLite 持久队列、全局单执行、FIFO、去重冷却、429 和重启恢复 | 不等价于多实例消息队列或高可用 worker |
| 项目自身供应链 | 共享运行时/前端精确锁定，自身 SBOM、许可、漏洞、Secret 与仓库卫生门可复现 | 漏洞结论是 2026-08-25 的时间截面 |
| 可移植启动 | 当前主机和模拟异用户环境通过；可按固定 Cisco 提交重建运行时 | 真正洁净 Windows Sandbox 仍待 P0-5 验收 |

## 3. 最新冻结验证

- P0-2 动态队列专项：`14 passed`；最大并发 running 为 1，FIFO 违反、重复新增任务和永久中间态均为 0。
- P0-4 自身供应链门：12/12 gate 通过；共享环境 126 个 Python 包、Windows x64 已安装 26 个 Node 包和 pnpm 锁内 50 个组件完成核对；已知漏洞 0、已验证凭据泄露 0、许可未知/越界 0、锁不匹配 0。
- Cisco 兼容冒烟：Skill 固定集完成；MCP 内容 6 项中 safe 3/unsafe 3；已知漏洞 fixture 检出 24 项 HIGH，安全 fixture 0 项；内部 pip-audit 失败会被复现脚本拒绝。
- 后端完整回归：`348 passed`。
- 前端 API 测试：`10 passed`。
- 前端生产构建：通过。
- P0-2 证据：`demo_web/artifacts/experiment/2026-08-24-dynamic-queue-recovery-dev-v1/`。
- P0-1 证据：`demo_web/artifacts/experiment/2026-08-24-portable-startup-dev-v1/`。
- P0-4 证据：`demo_web/artifacts/experiment/2026-08-24-project-supply-chain-hygiene-dev-v1/`。
- M3 600 条密封回归结论仍为 `supported_with_tradeoff`，未因工程改造重新调规则。

## 4. M5 完成度

| 优先级 | 工作项 | 状态 | 下一验收门 |
| --- | --- | --- | --- |
| P0-1 | 可移植启动与运行时重建 | 已完成 | P0-5 再做洁净 VM 证明 |
| P0-2 | 动态互斥、队列、去重、恢复 | 已完成 | P2-2 再做外部 worker/DB |
| P0-3 | 当前状态单一真值 | 已完成 | 文档契约测试持续防漂移 |
| P0-4 | 项目自身供应链卫生 | 已完成 | 依赖/运行时/许可/SBOM/Secret 门持续执行 |
| P0-5 | Windows Sandbox 发布门 | **下一项** | 新克隆到四链 E2E 的真实 VM 证据 |
| P1 | 受控试点工程能力 | 未完成 | 隔离、独立评测、任务体验、CI、能力健康 |
| P2 | 生产化控制面 | 未完成 | 身份租户、持久平台、强沙箱、治理、准入、SLO |

详细验收合同与实施顺序见 `demo_web/docs/M5_ENGINEERING_EXECUTION_PLAN.md`，勾选进度见 `demo_web/CHECKLIST.md`。

## 5. 明确不主张

- 不主张已达到生产可用或可直接接入真实政企生产网。
- 不主张 Docker/WSL2 等同于虚拟机级恶意代码隔离。
- 不主张可安全执行第三方 Skill、MCP Server、未知镜像或数据集恶意样本。
- 不主张受控 fixture 的通过结果能证明某个外部组件安全。
- 不主张当前身份令牌、SQLite 和单进程调度已经满足多租户、高可用与合规审计。
- 不主张旧阶段报告中的测试总数、下一步或“最终”字样代表当前状态。

## 6. 文档解释规则

1. `CURRENT_STATUS.md`：唯一当前状态、发布判断和下一工程节点。
2. `QUICKSTART.md`、`SECURITY.md`、`demo_web/docs/API_V1_CONTRACT.md`：当前操作、安全和接口契约。
3. `demo_web/docs/M5_ENGINEERING_EXECUTION_PLAN.md`、`demo_web/PLAN.md`、`demo_web/CHECKLIST.md`：当前执行细节。
4. `M1`–`M4`、日期化报告、`REPRODUCTION_REPORT.md`、旧评委审查：历史时间截面，仅证明当时实验，不覆盖本文件。

每次里程碑提交必须同步本文件中的基线、测试数、完成度和下一项；若尚未同步，不得把新里程碑称为已冻结。
