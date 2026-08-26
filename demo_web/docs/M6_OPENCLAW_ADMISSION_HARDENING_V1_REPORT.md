# M6-3 OpenClaw 准入审计与隔离加固报告

> 验证日期：2026-08-26
> 开发分支：`openclaw-install-policy`
> 基线提交：`8958cd3`
> 结论：`supported_for_skill_install_admission_with_documented_platform_limits`

## 1. 本轮目标

M6-2 已证明真实 OpenClaw 能在安装提交前调用 Aegis Chain。本轮补齐三项真实政企平台必需控制：

1. 第三方扫描器不能继承平台进程中的云密钥、管理员令牌和带认证信息的代理变量。
2. 每次安装准入必须形成最小化、可校验的持久审计记录；审计失败不得放行。
3. 部署前必须一次性检查文件、版本、哈希、策略、环境隔离、安全/恶意固定样本和审计链。

检测规则、默认准入阈值和 M3 密封回归结论均未修改。

## 2. 扫描进程环境白名单

旧实现复制整个服务环境后仅删除4个已知 API Key，无法覆盖政企平台常见的云密钥、GitHub Token、管理员令牌和代理凭据。本轮改为从空字典构建环境，只传入：

- Windows 启动兼容项：`SYSTEMROOT/WINDIR/COMSPEC/PATHEXT`；
- 固定运行项：UTF-8、模型离线开关和成本表离线开关；
- 由固定 Cisco 运行时和 Windows 系统目录组成的 `PATH`；
- 仓库缓存内的 `TEMP/TMP/XDG_CACHE_HOME`；
- 仓库缓存内合成的 `USERPROFILE/APPDATA/LOCALAPPDATA`。

真实用户目录、`OPENAI_API_KEY`、云凭据、GitHub Token、`HTTP_PROXY` 等不进入扫描器。第一版完全移除用户目录变量后，真实 `pip-audit` 因 Windows Known Folder API 失败；最终使用合成目录恢复兼容，没有重新继承真实用户环境。

真实冒烟结果：

| 链路 | 结果 |
|---|---|
| Cisco Skill Scanner | 1 个结果，正常完成 |
| Cisco MCP Scanner | 6 个结果，其中 unsafe 3，正常完成 |
| pip-audit | 1 个依赖、14 个漏洞，正常完成 |

边界：需要企业认证代理的部署不能依赖隐式环境继承，应后续增加管理员显式配置、凭据托管和审计；在此之前网络不可达会失败关闭。

## 3. 安装准入审计链

新增独立 SQLite 审计库，默认位于运行数据目录，也可通过 `AEGIS_OPENCLAW_AUDIT_DB` 指定。每条记录只保留：

- OpenClaw 版本、目标类型和目标名；
- 扫描前源码树 SHA-256，不保存源码或绝对源码路径；
- allow/warn/block、首要原因码、最多3条规则编号和严重度；
- 执行耗时、REVIEW 兼容模式和时间；
- 前序记录哈希与当前链哈希。

数据库事务使用 `BEGIN IMMEDIATE` 串行追加；触发器拒绝应用层 UPDATE/DELETE。独立校验工具可重算整条哈希链。它不是外部 WORM、可信时间戳或管理员不可篡改存储，生产环境仍需把链头和事件转发到企业 SIEM/审计平台。

安全性质：

- allow 只有在审计记录成功提交后才返回；
- 审计写入异常改为 `AEGIS_POLICY_AUDIT_FAILED/block`；
- 非法 JSON、协议错误和扫描异常也记录阻断事件；
- 审计展示不返回 sourcePath 和原始 Finding 证据正文。

## 4. 部署前检查

新增 `openclaw_install_policy_preflight.py`，默认执行以下必需门：

- 策略 CLI、Windows 代理、配置示例、策略文件和 Cisco Scanner 文件存在；
- Cisco Skill Scanner 版本固定为 `2.0.13.dev3+g4dee90371`；
- Scanner 可执行文件 SHA-256 为 `b31b66fce1b8466ba5c49e1084ee972b746e00d4ebdcaeab78ad6b38a0dce366`；
- 子进程环境键全部落在白名单；
- `admission_policy.yaml` 可失败关闭加载；
- 哈希固定安全 Skill 得到 allow；恶意外传 Skill 得到 block；
- 两次准入审计记录完整性链有效。

真实完整 preflight：`ready=true`，安全为 allow、恶意为 block、审计2行有效。`--skip-fixed-scans` 仅用于诊断，并明确返回非就绪，不能作为部署通过证据。

该工具不会修改 OpenClaw。目标机器上的绝对路径、Windows ACL、workspace/state 隔离和稳定版 REVIEW→block 配置仍需人工核验。

## 5. 真实 CLI 审计结果

同一审计库连续处理两个固定请求：

| 请求 | 决策 | 关键证据 | 耗时 |
|---|---|---|---:|
| `aegis-m6-3-safe` | allow | INFO 3条 | 4420 ms |
| `aegis-m6-3-risky` | block | CRITICAL 2条、WARN 1条 | 4422 ms |

审计校验：2行、链有效，最终链头：

`0a14b264e6e87cb82db4b0ba11f68ec7397f7a96926e6af2815711f4bf1cb101`

## 6. 当前可主张与边界

可以主张：

> OpenClaw Skill 安装准入已具备扫描器环境白名单、审计失败关闭、最小化 SQLite 完整性链和一键部署前检查；真实 Cisco Skill/MCP/依赖扫描与安全/恶意准入均通过。

不可以主张：

- 审计库等价于外部 WORM、可信时间戳或 SIEM；
- 企业认证代理和凭据托管已经完成；
- Plugin/MCP 安装包准入已经实现；
- OpenClaw 可确认 warn 或 Beta Windows ACL 门已经通过；
- 已达到真实政企生产平台标准。

## 7. 下一步

进入 M6-4，先解析 OpenClaw 当前实际传入的 plugin 目录结构，再实现最小 Plugin/MCP 包准入；无法被现有静态链可靠覆盖的类型继续失败关闭，不为追求“全支持”放宽策略。
