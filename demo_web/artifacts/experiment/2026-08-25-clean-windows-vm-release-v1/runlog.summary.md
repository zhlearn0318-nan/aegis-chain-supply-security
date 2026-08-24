# P0-5 真实 Windows VM 运行日志摘要

## 2026-08-25：环境建立

- 从 Oracle 官方发布取得并验证 VirtualBox 7.2.16 安装器；仅安装核心应用组件，没有 Extension Pack、桥接/Host-only、USB 或 Python 扩展。
- 从 Microsoft Evaluation Center 取得 Windows 11 Enterprise Eval 25H2 ZH-CN x64 ISO；文件大小 7,371,034,624 字节，SHA-256 与官方哈希表一致。
- 创建 `Aegis-P0-5-Win11`：EFI64、Secure Boot、TPM 2.0、4 vCPU、6144 MB、64 GB 动态 VDI、NAT、禁用共享剪贴板/拖放/USB/音频/VRDE。
- 无人值守 dry-run 曾把一份尚未使用的初始随机 guest 密码显示到控制台；在实际安装前已立即轮换，旧值从未用于 guest。当前密码文件 ACL 受保护且不记录密码正文。
- 安装在 42% 阶段因宿主 Hyper-V 兼容层与来宾 SysMain 资源争用长时间不前进；只读内省确认 Windows Build 26200 和 SysMain PID，临时停止 SysMain 后安装立即继续到 100%。没有修改启动类型，正常重启后恢复默认自动启动。
- Guest Additions `7.2.16 r174877` 安装完成；正常重启后 RunLevel 按 0→1→2→3 恢复，`guestcontrol cmd /c ver` 成功。

## 2026-08-25：引导与网络预检

- guest 通过 `http://10.0.2.2:7897` 对 GitHub HEAD 请求得到 200。
- `Initialize-AegisAcceptanceGuest.ps1`、`Invoke-AegisReleaseAcceptance.ps1`、`toolchain.windows-x64.json` 复制到 `C:\AegisBootstrap`。
- 三个文件的宿主/guest SHA-256 完全一致。
- 未把宿主 `gh` 当前高权限 token 写入 guest。正式认证路线改为单仓库只读 Deploy Key。

## 2026-08-25：认证硬化实现

- 控制器新增 SSH Deploy Key 参数，要求私钥与 `known_hosts` 成对存在，仓库 URL 必须使用 GitHub 官方 SSH 端点，且不能与 GitHub token 同时启用；可删除私钥被限制为引导目录下固定的 `aegis-readonly-deploy-key`，避免形成任意路径删除面。
- 使用锁定 MinGit 自带 `ssh.exe`，强制 `BatchMode`、`IdentitiesOnly`、`StrictHostKeyChecking=yes`，不读取用户/全局 SSH 配置。
- clone 尝试结束后无论成功或失败都删除 guest 私钥，并恢复原 Git 环境变量；attestation 记录认证模式和私钥残留布尔值，不记录密钥内容。
- PowerShell AST 解析通过；发布验收合同专项 `9 passed`。第一次测试受系统临时目录 ACL 影响，改用仓库内隔离临时目录后全部通过；无断言失败。

## 2026-08-25：第一次真实主运行（失败证据保留）

- 经用户明确授权，将一次性公钥登记为仓库级只读 Deploy Key；GitHub 返回 `read-only`。私钥只复制到 guest 引导目录，ACL 仅允许 `aegisadmin`、SYSTEM 和 Administrators。
- GitHub 官方 API `meta` 返回的 ED25519/ECDSA/RSA 主机指纹与本地 `known_hosts` 三项逐一相符；SSH 固定使用 `ssh.github.com:443`。
- 在不存在旧工作区的 guest 中启动主运行；四个锁定工具下载完成并通过哈希/SRI 校验，MinGit、Node、Miniforge、pnpm 均由引导器独立安装。
- 远端 `refs/heads/dynamic-audit-v1` 与期望提交 `35953be33c120caa316831aa42476029059cb1d7` 一致；从私有 GitHub 仓库全新 clone，detached checkout 成功。
- VM 证明、锁定工具链、远端引用、全新 clone 与引导前负向 preflight 均通过，生成 `fresh_clone_attestation.json`。
- 主运行在 `01-bootstrap-runtimes` 以退出码 1 失败，总门禁以退出码 33 失败；`.runtime_skill` 已部分生成，MCP 运行时与两个 Cisco 源码目录尚未生成。该次证据固化到 `attempt-1-failed/evidence/`，不得作为通过证据。
- clone 的 `finally` 清理后独立检查 guest 私钥路径，结果为不存在；GitHub Deploy Key 暂时保留，仅用于修复后的第二次正式运行。
- 原日志只剩 `RemoteException`，暴露出 Windows PowerShell 5.1 在全局 `ErrorActionPreference=Stop` 下把原生命令 stderr 提前转为终止错误的可观测性缺陷。
- 在独立诊断前缀用同一 Miniforge/代理重放 `conda create python=3.11 pip`，结构化结果 `success=true`、退出码 0，支持首次失败为瞬时依赖获取/Conda 子进程问题；因原始 stderr 丢失，不对更具体根因作无证据断言。

## 2026-08-25：失败日志修复

- `Invoke-LoggedStep` 仅在外部命令收集窗口内使用 `Continue` 捕获 stdout/stderr，随后恢复原错误策略；最终判定仍以显式退出码失败闭锁。
- 每个步骤在判定前写入独立 `.step.json`，记录命令、参数、开始时间、耗时、退出码与日志文件名，失败时同样保留。
- PowerShell AST 解析通过；发布合同专项 `9/9` 通过。
- 从正式门禁脚本 AST 提取真实 `Invoke-LoggedStep` 做行为测试：故意写入 stderr 并退出 7，日志保留哨兵、步骤 JSON 保留退出码 7，验证没有把失败误判为通过。
- 宿主完整后端回归 `357/357` 通过（仅保留已知 Starlette/httpx 弃用警告）；项目自身供应链门禁 `12/12` 通过，包含 `verified_secrets_zero=true`，失败证据未检出认证材料。

## 当前状态

- 状态：`partial / attempt 1 failed / fix validated locally`。
- 当前没有正式通过指标或成功报告；第一次失败证据已保留且明确标记为非发布验收。
- 下一动作：提交并推送日志修复，将更新控制器复制到 guest，使用新的远端固定提交和全新工作目录执行第二次完整主运行。
