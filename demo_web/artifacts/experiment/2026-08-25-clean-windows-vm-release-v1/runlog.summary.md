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
- 未把宿主 `gh` 当前高权限 token 写入 guest。正式认证路线改为单仓库只读 Deploy Key；该外部仓库变更等待用户明确授权。

## 2026-08-25：认证硬化实现

- 控制器新增 SSH Deploy Key 参数，要求私钥与 `known_hosts` 成对存在，仓库 URL 必须使用 GitHub 官方 SSH 端点，且不能与 GitHub token 同时启用；可删除私钥被限制为引导目录下固定的 `aegis-readonly-deploy-key`，避免形成任意路径删除面。
- 使用锁定 MinGit 自带 `ssh.exe`，强制 `BatchMode`、`IdentitiesOnly`、`StrictHostKeyChecking=yes`，不读取用户/全局 SSH 配置。
- clone 尝试结束后无论成功或失败都删除 guest 私钥，并恢复原 Git 环境变量；attestation 记录认证模式和私钥残留布尔值，不记录密钥内容。
- PowerShell AST 解析通过；发布验收合同专项 `9 passed`。第一次测试受系统临时目录 ACL 影响，改用仓库内隔离临时目录后全部通过；无断言失败。

## 当前状态

- 状态：`partial / external authorization pending`。
- 主运行尚未启动，不存在正式通过指标或成功报告。
- 下一动作：经用户授权创建临时只读 Deploy Key，推送当前认证硬化提交，复制更新控制器并执行真实 VM 全链路。
