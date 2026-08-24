# P0-5 真实 Windows VM 发布门主运行计划

## 1. 运行身份

- run id：`2026-08-25-clean-windows-vm-release-v1`
- experiment tier：`main/test`
- 分支：`dynamic-audit-v1`
- 基线提交：`2390d58c2aa2acb6b1ed95d8384ed5509177d5a1`
- 选定路线：在 Oracle VirtualBox 中安装独立 Windows 11 Enterprise Eval guest，使用哈希锁定工具链和临时、单仓库只读 Deploy Key 从私有远端全新克隆，再执行 P0-5 四链发布门。Deploy Key 只用于克隆，严格校验 GitHub SSH 主机密钥，私钥在克隆结束后从 guest 删除。

## 2. 研究与验收问题

- 研究问题：没有项目运行时和开发缓存的新 Windows VM，能否仅依赖固定引导文件、官方哈希锁定工具和私有远端提交，重建 Aegis Chain 并完成完整发布验收？
- 零假设：VM 身份、新克隆、引导前负面控制、工具完整性、回归、四链 HTTP、失败闭锁、导出或残留门至少一项不能通过。
- 备择假设：全部必需门通过，证据可绑定到独立 VM、远端提交和下载哈希，且失败/降级不被误记为成功。
- 研究类型：工程主验收与可复现性验证。
- 研究目标：把 P0-5 从 `implementation_ready_vm_evidence_pending` 提升为有真实 guest 证据的发布门结论。

## 3. 基线与可比边界

- 检测规则、策略、SkillTrustBench 冻结结果和受控动态 fixture 保持只读。
- 不执行第三方不可信代码；动态链只运行仓库内哈希锁定自建 fixture。
- Docker Skill 闭包在 guest 无 Docker 时允许结构化 `503` 降级，但基础机制动态链必须通过。
- 正式结果只绑定传入的远端 40 位提交；宿主机烟雾结果不替代 VM 结果。

## 4. 必需指标与成功条件

| 证据项 | 成功条件 |
| --- | --- |
| VM 身份 | VirtualBox 厂商/型号/BIOS/主板证据通过，MachineGuid 仅保存 SHA-256 |
| 工具链 | MinGit、Node、Miniforge 三个 SHA-256 与 pnpm SRI 全部现场一致 |
| 私有远端 | `ls-remote`、clone HEAD 与预期提交一致，origin 与传入 SSH URL 一致 |
| 清洁性 | clone 目标原先不存在；引导前 Skill/MCP 必需运行时缺失并失败 |
| 回归 | 后端、前端测试与生产构建全部通过 |
| 自身供应链 | 12/12 gate 通过 |
| HTTP 链 | Skill、MCP、依赖静态和机制动态 `4/4` 完成 |
| 导出 | JSON/Markdown/SBOM `7/7` 内容与任务身份一致 |
| 失败闭锁 | 关闭代理与新缓存下依赖任务为 `failed / UNKNOWN / SCAN_EXECUTION_FAILED` |
| 清理 | 上传临时目录、动态工作区、审计容器和 tracked 改动为 0 |

## 5. 最小代码变更图

| 路径 | 变更 | 原因 | 风险控制 |
| --- | --- | --- | --- |
| `release_vm/Initialize-AegisAcceptanceGuest.ps1` | 增加只读 Deploy Key 模式 | 避免向一次性 VM 注入高权限 GitHub CLI token | 仅允许 GitHub 官方 SSH 端点；私钥/known_hosts 必须是引导目录下固定名称，严格主机校验、禁交互、认证互斥、克隆后删除私钥 |
| `backend/tests/test_release_acceptance_contract.py` | 增加认证安全合同测试 | 防止后续退化到弱主机校验或私钥残留 | 保留既有 token 模式兼容性 |
| `docs/M5_P0_5_CLEAN_WINDOWS_VM_RELEASE_GATE.md` | 同步真实 VM 状态和推荐认证方法 | 状态真值可复核 | 未完成正式 run 前不宣称通过 |

## 6. 执行设计

- smoke：PowerShell AST 解析；发布验收合同专项；VM 控制通道与代理 HEAD 请求；引导文件宿主/来宾 SHA-256 对比。
- full run：远端 HEAD 冻结后，在 guest 执行 `Initialize-AegisAcceptanceGuest.ps1`，不使用 `PrepareOnly`，由其连续调用正式 release gate。
- 预期输出：guest 外部 `C:\AegisAcceptance\evidence`，回收后固化到本目录；包含 attestation、run/metrics/summary/claim、日志和 artifact manifest。
- 停止条件：VM 身份不能证明、远端提交漂移、下载哈希不符、私钥未删除、引导前负面控制未失败、第三方样本进入执行面或任一失败被标成成功。
- 放弃条件：只有关闭宿主安全功能、放宽 SSH 主机校验、传入高权限长期 token 或复用宿主目录才能继续。
- 最强替代解释：一次真实 VM 通过只证明固定 Windows/工具链/提交组合可重建，不等于生产高可用或跨平台普适性。

## 7. 运行环境

- provider：Oracle VirtualBox `7.2.16 r174877`
- guest：Windows 11 Enterprise Evaluation 25H2 ZH-CN x64，Build `26200.6584`
- guest UUID：`48b4f094-9481-4f54-a559-bab0518531ac`
- guest 资源：4 vCPU、6144 MB、64 GB 动态 VDI、EFI Secure Boot、TPM 2.0、NAT
- ISO SHA-256：`7b4ac87391b659f7724229682b642256289a1c00504056249f0f12029157d3d2`
- 网络：guest 经 `http://10.0.2.2:7897` 访问宿主本地代理；代理不含凭据。

## 8. 恢复与下一路由

- 下载中断：保留已下载文件但每次重验哈希；不得跳过校验。
- clone 失败：吊销并删除本轮 Deploy Key，删除失败 workspace 后以新 run id 重试；不得复用半成品 clone。
- gate 失败：保存 `failure.json` 和日志，不生成成功 summary；只修复具体阻断后启动新运行。
- 成功：回收证据、独立验证、同步唯一状态真值、提交并推送，然后进入 P1-1 静态扫描 worker 隔离。

## 9. 修订记录

| 时间 | 变更 | 原因 | 对可比性的影响 |
| --- | --- | --- | --- |
| 2026-08-25 | 从高权限 token 方案切换为临时只读 Deploy Key | 减少 guest 内凭据权限和残留风险 | 不改变仓库内容、提交或验收指标，只改变认证通道 |
| 2026-08-25 | 安装阶段临时停止 SysMain，重启后恢复自动启动 | Hyper-V 兼容层下 SysMain 阻塞 42% 安装进度 | 只影响 VM 安装耗时，不影响正式 clone 后的验收内容 |
