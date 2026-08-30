# M10 OpenClaw 最终集成与 Windows 一键部署说明

> 后续状态：本文件记录五侧边栏和固定样本准入阶段。真实 ZIP/文件夹上传安全合同请以 [`M11_OPENCLAW_FORMAL_SKILL_UPLOAD_ADMISSION.md`](M11_OPENCLAW_FORMAL_SKILL_UPLOAD_ADMISSION.md) 为准；最终单入口界面请以 [`M12_OPENCLAW_UNIFIED_SECURITY_CENTER_RELEASE.md`](M12_OPENCLAW_UNIFIED_SECURITY_CENTER_RELEASE.md) 为准。

> 状态日期：2026-08-29
> 适用分支：`openclaw-final-integration`
> 固定 OpenClaw 版本：`2026.7.1-2`
> 发布判断：比赛现场演示版本 **READY**；真实政企生产发布仍为 **NO-GO**。

## 1. 本阶段完成结论

Aegis Chain 已作为 OpenClaw 的安装前供应链安全引擎接入，而不是并列运行的独立演示网页。最终版本同时提供：

1. Skill 安装前自动静态审计与 Docker 隔离试运行；
2. Plugin 安装前自动静态审计；
3. MCP Server 配置提交前审查，并在放行后通过 OpenClaw 官方 `mcp set` 写入、`mcp show` 复核；
4. OpenClaw 左侧五个 Aegis 页面：准入、报告、审计、规则、MCP；
5. 自定义结构化规则与 YARA 的新增、修改、启用、停用和删除，保存后下一次扫描立即生效；
6. SQLite 最小化审计、SHA-256 追加哈希链、单条 PDF 报告导出；
7. Windows 一键安装/修复脚本，固定版本、备份配置、失败回滚并执行完整预检。

现场演示版默认当前 OpenClaw 用户拥有全部 Aegis 管理权限；尚未实现多用户 RBAC。

## 2. 最终系统架构

```text
OpenClaw Web Control UI
├─ Aegis 准入：固定 SkillTrustBench 样本真实安装演示与流式终端
├─ Aegis 报告：准入结果列表、单条详情、PDF 导出
├─ Aegis 审计：事件列表、哈希链完整性
├─ Aegis 规则：结构化规则/YARA CRUD、启停和变更链
└─ Aegis MCP：MCP Server 配置提交前审查
        │
        ▼
OpenClaw Gateway 插件（官方 Tab + HTTP Route 扩展点）
        │
        ├─ Skill / Plugin：security.installPolicy 自动调用
        └─ MCP：Aegis 管理接口调用后使用官方 mcp set/show 提交与复核
        │
        ▼
Aegis Chain 后台安全引擎
├─ Cisco AI Skill Scanner
├─ Cisco AI MCP Scanner
├─ pip-audit
├─ Aegis 政企静态规则与上下文/数据流分析
├─ 自定义结构化规则与 YARA
├─ Docker Skill 隔离试运行（静态允许后才执行）
└─ 统一策略、Finding、审计与报告
```

## 3. 三类对象的准入方式

### 3.1 Skill

OpenClaw 执行 `skills install` 时自动调用 `security.installPolicy`。Aegis 先运行静态扫描；静态 BLOCK 时不启动容器。静态允许时，在 `required` 模式下进入 Docker 隔离试运行。动态结果只能维持或提高风险，不能把静态 BLOCK 降级为 ALLOW。

容器安全合同包括：断网、非 root、只读根文件系统、`cap-drop=ALL`、`no-new-privileges`、PID/CPU/内存限制、受限 tmpfs、固定摘要镜像和运行后残留检查。

### 3.2 Plugin

OpenClaw 执行 `plugins install` 时自动调用同一安装策略，但走 Plugin 专用 manifest、入口、生命周期、依赖锁、二进制覆盖、运行时下载和随包 MCP 声明规则。Aegis 自身插件也必须经过这条策略安装，不使用绕过开关。

### 3.3 MCP

OpenClaw `2026.7.1-2` 的安装策略目标只覆盖 Skill 和 Plugin，因此配置型 MCP 通过“Aegis MCP”页面提交。系统先检查：

- 远程地址是否使用 HTTPS（本机 loopback HTTP 除外）；
- 是否通过 `npx`、`uvx`、`pipx` 在运行时下载代码；
- 是否经 Shell 启动或使用解释器代码加载参数；
- 是否关闭 TLS 校验；
- URL、Header、环境变量是否嵌入凭据；
- 是否存在 `NODE_OPTIONS`、`PYTHONSTARTUP` 等运行时注入；
- 是否设置最小工具过滤范围；
- 可选 Tool、Prompt、Resource 离线发现对象是否命中 Cisco MCP Scanner 与 Aegis MCP 规则。

只有 ALLOW 才进入提交。系统先用 `openclaw mcp show --json` 在内存中快照旧配置，再调用官方 `openclaw mcp set`；写入后必须再次 `show` 并逐字段比较。提交或复核失败时，有旧配置则恢复旧值，原来不存在时才调用 `mcp unset`。审计只保存配置 SHA-256、决策和规则 ID，不保存明文配置或秘密。

## 4. 自定义规则管理

管理员页面不接受任意 Python 或 Shell 规则，只允许两类安全表达：

1. 结构化规则：限定作用域、文件名或内容包含条件、严重度和处置；
2. YARA：保存前必须在本机编译成功，扫描时有文件数与单文件大小上限。

规则注册表采用 revision 乐观并发控制和临时文件原子替换。页面修改成功后无需重启服务，下一次 Skill、Plugin 或 MCP 扫描立即加载。每次新增、修改、启停和删除都写入独立 JSONL 哈希链。

## 5. 报告与审计

- 准入审计存储：`demo_web/data/openclaw-final/admission_audit.db`；
- 自定义规则：`demo_web/data/openclaw-final/custom_rules.json`；
- 规则变更链：同目录 `custom_rule_changes.jsonl`；
- 安装回执：同目录 `installation_receipt.json`；
- 原始源码、Prompt、密钥和值不进入长期审计；
- 单条报告由本机 Microsoft Edge 无头打印为 A4 PDF，不调用云服务。

本次最终 PDF：`output/pdf/Aegis-OpenClaw-Final-Acceptance.pdf`，对应审计序号 39。

## 6. Windows 一键安装

将完整项目目录复制或克隆到目标 Windows 电脑后，双击：

```text
Install_Aegis_OpenClaw_Final.cmd
```

窗口会保持打开，不再出现“闪一下立即关闭”。脚本依次完成：

1. 检查 Node.js、Git、Miniconda、Docker Desktop；缺失时使用 winget 安装；
2. 固定 OpenClaw `2026.7.1-2` 与 pnpm `11.19.0`；
3. 从 Cisco 官方固定提交重建 Skill/MCP Scanner，并按哈希锁安装依赖；
4. 启动 Docker，拉取并核对固定摘要 Python 镜像；
5. 备份 `openclaw.json`；
6. dry-run 后写入 Skill/Plugin 失败闭锁策略；
7. 在策略已生效的情况下安装 Aegis 插件；
8. 安装/重启 OpenClaw Gateway；
9. 探活五个页面并运行 `preflight.ps1 -RequireDynamic`；
10. 写入安装回执并打开 OpenClaw Web 控制台。

安装器失败时会恢复原 OpenClaw 配置。机器专属绝对路径只存在运行期配置，不提交 Git。

只读复核命令：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\install_openclaw_final.ps1 `
  -VerifyOnly -SkipDependencyInstall -NoLaunch
```

## 7. Docker Desktop 已知 Windows 故障恢复

本机 Docker Desktop 4.86.0 曾因异常退出遗留 AF_UNIX ReparsePoint，错误目标为：

- `%LOCALAPPDATA%\Docker\run\dockerInference`；
- `%LOCALAPPDATA%\docker-secrets-engine\engine.sock`。

它们是 0 字节临时套接字，不是镜像、容器或卷。安装器只在 `backend.error.json` 精确匹配“file cannot be accessed”及上述路径时触发恢复：备份 Docker 设置、关闭 Model Runner/Inference、把两个仅含重解析点的父目录改名为 `*.aegis-stale-*`，再重新启动。若目录出现非套接字内容，安装器拒绝自动处理。

本次恢复后实测 Docker Desktop 4.86.0、Engine 29.7.2、API 1.55 正常，固定镜像 ID 匹配。Docker Model Runner 与 Aegis 容器动态审计无依赖关系。

## 8. 2026-08-29 最终真实验收

| 序号 | 对象 | 场景 | 决策 | 提交状态 | 关键证据 | 引擎耗时 |
|---:|---|---|---|---|---|---:|
| 35 | Plugin | Aegis 自身插件在策略开启后安装 | ALLOW | 已链接并启用 | `AEGIS_PLUGIN_COVERAGE_SUMMARY` | 139 ms |
| 36 | Skill | SkillTrustBench `case_00906` | ALLOW | 已安装 | `AEGIS_DYNAMIC_EXECUTION_CLEAN` | 13,674 ms |
| 37 | Skill | SkillTrustBench `case_01084` | BLOCK | 未安装 | Prompt Injection、远程执行链；动态 0 次 | 8,022 ms |
| 38 | MCP | HTTPS + OAuth +工具白名单 | ALLOW | `mcp set` 后 `show` 复核成功 | 配置 SHA-256 | 36,819 ms |
| 39 | MCP | `npx` 运行时下载 + 明文 API Key | BLOCK | 未写入 | runtime fetch、embedded secret | 5 ms |
| 40 | Skill | 浏览器真实点击恶意按钮 | BLOCK | 未安装 | 终端 6/6、进度 100%、链有效 | 7,333 ms |
| 41 | MCP | 事务式新配置提交 | ALLOW | 已写入、精确复核后清理 | 旧值快照→set→show；临时配置已 unset | 51,261 ms |

验收后的两个安全 MCP 测试配置已使用官方 `mcp unset` 清理；BLOCK 配置从未写入。审计证据保留。

其他验收结果：

- 完整后端回归：`450 passed, 1 skipped`；跳过项仅为当前 Windows 测试账户无符号链接创建权限；
- 前端 API 测试：`10 passed`；
- 前端生产构建：通过；
- 自定义规则 + MCP 新增专项：`15 passed`；
- 五个 OpenClaw 页面：HTTP 200；
- 全平台预检：24 项 PASS，0 WARN，`dynamic_ready=true`；
- 最终审计：41 条，SHA-256 哈希链有效；
- PDF：A4 单页，90,040 字节，`%PDF-1.4`，无内嵌 JavaScript，人工渲染检查通过。

## 9. 比赛演示建议

1. 双击一键安装脚本，展示最终 `READY` 和 0 警告预检；
2. 打开 OpenClaw 左侧“Aegis 准入”，先安装安全 Skill，再阻断恶意 Skill；
3. 展示底部终端的真实 `openclaw skills install`、心跳、规则和审计序号；
4. 打开“Aegis MCP”，展示 HTTPS 配置放行与 `npx + API_KEY` 阻断；
5. 打开“Aegis 审计”，指出 ALLOW/BLOCK 事件和有效哈希链；
6. 打开“Aegis 报告”，导出 PDF；
7. 打开“Aegis 规则”，演示新建、停用、启用规则并说明立即生效。

## 10. 仍需如实说明的边界

- 已达到比赛现场可演示和当前主机可重复部署，不等于真实政企生产可用；
- 尚未在第二台洁净 Windows 电脑或真实 VM 完成完整一键部署证据；
- 当前用户默认拥有全部管理权限，未完成 SSO、RBAC、双人审批和多租户隔离；
- 本地 SQLite 哈希链不等于外部 WORM、可信时间戳或 SIEM；
- Docker/WSL2 不等于恶意代码专用虚拟机，Python audit hook 不能对抗所有主动规避；
- MCP 当前执行配置与离线发现对象审查，不主动连接未知远程 MCP 做在线攻击测试；
- 当前版本不宣称可安全运行任意未知第三方 Skill。
