# M6-4 OpenClaw Plugin/MCP 安装准入报告

> 日期：2026-08-26
> 分支：`openclaw-install-policy`
> 基线：`7cbcabe`
> 结论：`supported_for_directory_native_plugins_and_manifest_mcp`

## 1. 实现范围

依据本机完整性核验的 OpenClaw `2026.8.1-beta.3` 官方包与稳定版 `2026.7.1-2` 真实 CLI，本轮确认 install policy 的 Plugin 请求提供暂存路径、Plugin 元数据和 `directory/file` 类型。v1 选择可靠的最小范围：

- 支持目录型原生 OpenClaw Plugin；
- 解析 `openclaw.plugin.json`、`package.json` 与 manifest 内 `mcpServers`；
- 显式兼容包返回 REVIEW；
- 单文件 Plugin、归档和缺少可验证 manifest 的包失败关闭；
- 不把 Plugin 伪装成 Skill，也不声称 Cisco Skill/MCP Scanner 覆盖 Plugin 源码。

OpenClaw `mcp add/set/configure` 管理的是配置定义，不经过 skill/plugin install policy。本轮覆盖的是 Plugin 随包 `mcpServers`，不是任意配置型远端 MCP 准入。

## 2. 新增检查

- 原生 manifest 的 `id`、`configSchema`；
- `package.json` 的 `openclaw.extensions` 存在、可解析且不逃逸目录；
- `preinstall/install/postinstall/prepare` 生命周期脚本；
- 非精确依赖、依赖存在但锁文件缺失；
- 二进制、原生扩展和嵌套归档覆盖缺口；
- Plugin 源码中的敏感数据流、不可信输入到执行、持久化和政企高危控制；
- MCP 的 npx/uvx/pipx 运行时下载、Shell/解释器加载参数、绝对宿主命令、越界工作目录；
- MCP 的非 HTTPS、关闭 TLS 校验、明文 Authorization/API Key 和 manifest 内凭据。

所有结果进入既有 Finding IR 和同一准入策略。规则/策略异常继续失败关闭，扫描前后整树哈希仍必须一致。

## 3. 真实 OpenClaw 结果

隔离配置将 `targets` 扩展为 `skill/plugin`，未修改用户原 OpenClaw 配置。

| 用例 | 真实稳定版结果 | 残留 |
|---|---|---:|
| 良性原生 Plugin + 本地 stdio MCP | exit 0，安装成功 | 1个预期 Plugin目录 |
| 声明 npx 运行时下载的 Plugin | exit 1，HIGH 1条，安装前阻断 | 0 |

良性安装过程中 OpenClaw 两次复核同一策略请求，因此与阻断请求合计形成3行审计记录；完整性链有效，链头为：

`02ec442a8e01a5c6345a6b8058e441be6bc2cd1e76e81da68a9a042fc2939f0d`

完整部署 preflight 现同时验证 Skill 安全/恶意和 Plugin 安全/阻断四个固定样本，结果 `ready=true`、审计4行有效。

## 4. 能力边界

可以主张：

> Aegis Chain 已在真实 OpenClaw 稳定版中完成目录型原生 Plugin 安装前准入；良性本地 MCP Plugin 可安装，声明运行时下载的 Plugin 被阻断且无残留。

不可主张：

- Cisco Scanner 已直接覆盖 Plugin 包；Plugin 使用自研包规则和通用源代码分析；
- 配置型 `openclaw mcp add/set` 已接入安装策略；
- Plugin 单文件、归档、所有兼容包格式均可自动放行；
- npm 生态恶意包检出率已经形成权威数据集结论；
- 安装后的 Plugin 运行时权限隔离、MCP 在线探测或企业 SIEM 已完成；
- 已达到政企生产可用。

## 5. 后续建议

比赛交付冻结当前保守边界。若继续生产化，应在 OpenClaw MCP 配置写入前新增独立 policy hook，对 stdio 命令、远端 URL、TLS、OAuth/SecretRef、工具过滤和审批模式做准入；同时为 Plugin 规则建立独立标注数据集，不使用 SkillTrustBench 指标替代。
