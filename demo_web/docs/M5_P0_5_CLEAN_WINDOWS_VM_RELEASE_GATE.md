# M5 P0-5 真实 Windows VM 发布门

> 状态：`guest_ready_main_run_pending`
> 日期：2026-08-25
> 分支：`dynamic-audit-v1`
> 结论边界：验收程序已经实现并在宿主机完成非正式烟雾测试，但尚未取得真实 Windows VM 的正式通过证据，因此 P0-5 尚未完成，系统仍为生产 `NO-GO`。

## 1. 为什么必须使用真实 VM

P0-5 要回答的不是“当前开发目录能否再次运行”，而是“一个没有开发缓存、没有预装 Cisco 运行时的新 Windows 环境，能否仅依据私有远端仓库和固定来源重建系统，并完成四条审计链”。

本机目录复制、换用户、Docker 容器或 WSL 都无法同时证明 Windows 主机身份、全新克隆和宿主缓存隔离，因此不能替代正式证据。当前宿主为 Windows 家庭版，不提供 Windows Sandbox；正式验收可使用 VirtualBox、VMware、QEMU/KVM、Parallels、Xen 或 Hyper-V/Sandbox 中具有独立硬件身份的 Windows guest。

## 2. 本阶段已经实现的组件

| 组件 | 作用 | 失败行为 |
| --- | --- | --- |
| `release_vm/toolchain.windows-x64.json` | 固定 Git、Node.js、Miniforge、pnpm 的版本、官方来源、许可和哈希 | 任一版本、SHA-256 或 registry integrity 不匹配即停止 |
| `release_vm/Initialize-AegisAcceptanceGuest.ps1` | 在 guest 内证明虚拟机身份、下载固定工具、核验远端 ref、执行全新克隆和引导前负面检查 | 物理机、目录模拟、旧目标目录、错误提交或已有运行时均拒绝 |
| `release_vm/Invoke-AegisReleaseAcceptance.ps1` | 重建运行时并依次执行回归、供应链自审、HTTP 端到端和残留检查 | 任一 gate 失败只写失败记录，不生成成功结论 |
| `tools/release/verify_vm_attestation.py` | 将外部 attestation 与当前仓库、提交、工具哈希和初始状态交叉验证 | attestation 不新鲜、位于仓库内或证据不一致即失败 |
| `tools/release/run_release_http_acceptance.py` | 通过真实 `/api/v1` 上传 Skill、MCP、依赖，触发动态 fixture，轮询并导出证据 | 仅允许 loopback；状态、哈希、Finding、策略或导出不符即失败 |

## 3. 信任链

正式结果必须满足下列连续关系：

1. guest 的厂商、型号、BIOS 和主板信息证明它是支持的真实 VM；
2. 机器 GUID 只以 SHA-256 形式写入外部 attestation，不泄露原始标识；
3. 远端 `dynamic-audit-v1` ref 必须精确等于传入的 40 位提交；
4. 目标目录在执行前不存在，由固定 MinGit 新克隆产生；
5. 克隆后的 HEAD、origin 和空工作区状态与 attestation 一致；
6. 引导前 Skill/MCP preflight 必须因缺少运行时失败，证明没有复用宿主环境；
7. 下载对象逐个核验哈希，pnpm 包核验 registry integrity；
8. 正式控制器与工具清单采用换行归一化哈希，避免 Git CRLF 转换造成假失败；
9. 所有测试、扫描、服务启动和导出都在这个已证明的 clone 中执行；
10. 成功前再次核验无残留临时上传、动态工作目录、审计容器和 tracked 改动。

## 4. 固定工具链

| 工具 | 固定版本 | 来源 | 完整性 |
| --- | --- | --- | --- |
| MinGit | `2.53.0.windows.3` | Git for Windows 官方 GitHub Release | SHA-256 固定 |
| Node.js | `24.15.0` Windows x64 ZIP | nodejs.org 官方发布目录 | SHA-256 固定 |
| Miniforge | `25.11.0-1` Windows x64 | conda-forge 官方 Release | SHA-256 固定 |
| pnpm | `11.19.0` | npm registry tarball | SRI integrity 固定 |

这些工具仅用于创建可重复的验收环境，不扩大产品运行时声明。其来源、许可和确切校验值以 `toolchain.windows-x64.json` 为机器可读真值。

## 5. 正式发布门

真实 VM 必须一次性通过以下 gate：

1. VM 硬件身份和外部 attestation；
2. 私有远端 ref 与预期提交一致；
3. 新目录克隆、HEAD/origin/空工作区一致；
4. 引导前 Skill 与 MCP 运行时均缺失的负面控制；
5. 固定工具下载安装对象完整性；
6. Cisco Skill/MCP 运行时从固定来源重建；
7. 后端完整测试；
8. 前端完整测试和生产构建；
9. 项目自身供应链门 `12/12`；
10. Skill、MCP、依赖三类真实 HTTP 上传及异步任务完成；
11. 受控机制动态 fixture 完成且 7 个预期检查全部通过；
12. 每个静态任务的 JSON/Markdown 和依赖 SBOM 共 7 份导出可用；
13. 全新 pip-audit 缓存与关闭代理下，依赖扫描必须 `failed / UNKNOWN / SCAN_EXECUTION_FAILED`；
14. 服务停止后无上传临时文件、动态工作目录、`aegis-dyn-*` 容器和 tracked 改动。

最终目录必须包含 `run_manifest.json`、`metrics.json`、`summary.md`、`claim_validation.md`、逐步日志和 SHA-256 制品清单。若失败，只保留 `failure.json` 和诊断日志，不得留下会被误解为成功的报告。

## 6. Docker 能力健康修正

此前只要动态 Skill 闭包配置和 fixture 存在，健康接口就可能显示 ready，即使 Docker Desktop 没有启动。现在 Skill 闭包健康检查同时验证：

- Docker CLI 可调用；
- 当前引擎为 Linux 容器引擎；
- 哈希锁定的审计镜像确实可解析；
- fixture 和 runner 配置完整。

不可用时 `/api/v1/health` 返回机器可读 `reason_code` 和说明，调用闭包接口得到结构化 `503 / DYNAMIC_AUDIT_NOT_READY`。基础机制动态 fixture 与 Docker Skill 闭包是两项独立能力，前者可用不再掩盖后者降级。

## 7. 本机非正式验证

为验证验收器本身，已在当前宿主执行过非正式烟雾测试：

| 项目 | 结果 |
| --- | --- |
| 发布验收合同专项 | `9 passed` |
| 后端完整回归 | `357 passed` |
| 前端测试 / 生产构建 | `10 passed` / 通过 |
| Skill、MCP、依赖、机制动态四链 | `4/4` 完成 |
| JSON、Markdown、SBOM 导出 | `7/7` 完成 |
| Docker 未启动时能力降级 | 健康显示不可用，闭包接口返回结构化 503 |
| 真断网依赖负面控制 | `failed / UNKNOWN / SCAN_EXECUTION_FAILED`，失败闭锁 |
| pnpm 官方 tarball | 8,776,044 字节；现场 SHA-512/SRI 与锁定值一致，解包后版本 `11.19.0` |
| 物理宿主负面控制 | 华硕物理机身份被拒绝，未进入下载或克隆步骤 |

这组结果只能证明脚本和接口契约可工作，不能证明洁净重建，因此不计作正式 P0-5 通过证据。

## 8. 真实 VM 执行方法

在新建 Windows VM 中，将 `demo_web/release_vm` 三个文件作为只读引导材料复制到 guest 外部目录。正式验收优先使用临时、单仓库只读 GitHub Deploy Key，而不是把宿主机的高权限 GitHub CLI token 注入 guest。私钥和从 GitHub 官方元数据固定的 `known_hosts` 必须成对提供：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Initialize-AegisAcceptanceGuest.ps1 `
  -ExpectedCommit '<dynamic-audit-v1 的完整 40 位提交>' `
  -RepositoryUrl 'ssh://git@ssh.github.com:443/zhlearn0318-nan/aegis-chain-supply-security.git' `
  -GitSshPrivateKeyPath 'C:\AegisBootstrap\aegis-readonly-deploy-key' `
  -GitSshKnownHostsPath 'C:\AegisBootstrap\github-known-hosts' `
  -ProxyUrl 'http://10.0.2.2:7897'
```

控制器使用锁定 MinGit 自带的 SSH 客户端，禁用交互和用户/全局 SSH 配置，强制 `IdentitiesOnly`、`BatchMode` 和 `StrictHostKeyChecking=yes`；Deploy Key 私钥在 clone 尝试结束后删除。Deploy Key 必须在证据回收后从 GitHub 仓库吊销。原有进程环境变量 token 模式仅保留兼容性，禁止与 SSH 模式同时启用。正式 evidence 默认位于 `C:\AegisAcceptance\evidence`，即仓库目录之外。

若 guest 必须通过宿主本地代理联网，可传入无凭据的 `-ProxyUrl "http://10.0.2.2:<port>"`，并在 VirtualBox NAT 上启用 localhost reachable。控制器拒绝含用户名、密码、路径、查询或片段的代理 URL，只在 attestation 中记录“是否配置代理”，不保留代理地址。

## 9. 当前阻塞与下一判定

- P0-4 与 P0-5 验收程序已推送至私有远端；正式运行前必须用 `git ls-remote` 取得 `dynamic-audit-v1` 当前完整 40 位 HEAD，并将同一值传给初始化器，禁止使用只存在于本机的提交。
- 当前已完成真实 VirtualBox guest 安装：Windows 11 Enterprise Eval 25H2 ZH-CN x64 Build `26200.6584`，Guest Additions `7.2.16 r174877` 达到桌面运行级别 3；受保护密码文件驱动的 `guestcontrol` 和经宿主无凭据代理访问 GitHub 均已通过。
- 三份引导文件已复制到 guest 外部目录，宿主/guest SHA-256 完全一致。正式 run 尚未启动，当前等待创建临时、单仓库只读 Deploy Key 的明确授权；不能把“VM 已安装”解释为 P0-5 已通过。

只有远端提交可取、真实 VM run 全部通过、证据清单逐项验真后，才能把决策改为 `clean_windows_vm_release_gate_passed`。在此之前保持 `guest_ready_main_run_pending` 和生产 `NO-GO`。
