# Aegis Admission UI for OpenClaw

该插件使用 OpenClaw 官方 Control UI 插件页机制，在左侧只增加一个“Aegis 安全中心”入口。进入后默认展示真实安全总览，并通过同层标签切换准入扫描、扫描报告、审计记录、规则管理和 MCP 准入。准入支持真实 `.zip` 和浏览器本地文件夹上传，执行静态审计与 Docker 隔离试运行；只有 `ALLOW` 才能安装，同名 Skill 必须在页面内确认后事务更新。

## 安装

在项目根目录执行：

```powershell
openclaw plugins install --link .\demo_web\openclaw_plugin\aegis-admission-ui
openclaw gateway restart
```

推荐在新 Windows 环境直接双击仓库根目录 `Install_Aegis_OpenClaw_Final.cmd`，由安装器完成固定版本、运行时、Docker、策略、插件、Gateway 和预检。

刷新 OpenClaw Web 控制台，在左侧选择“Aegis 安全中心”。也可以直接访问：

```text
http://127.0.0.1:18789/plugin?plugin=aegis-admission-ui&id=admission
```

## 运行要求

- OpenClaw `security.installPolicy` 已启用且目标包含 `skill` 与 `plugin`；
- `AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY=required`；
- Docker Desktop Linux Engine 可用；
- 项目保留固定版 SkillTrustBench 样本和审计运行时。

MCP 配置准入通过安全中心的“MCP 准入”标签执行；放行时使用 OpenClaw 官方 `mcp set` 写入并用 `mcp show` 复核，阻断时不修改配置。

## 正式准入流程

1. 选择 `.zip` 或本地 Skill 文件夹；
2. 上传后执行静态审计，静态允许才进入 Docker 隔离试运行；
3. 最终 `ALLOW` 且审计链有效时启用安装按钮；
4. 安装前复核内容哈希，并由 OpenClaw 原生策略再次扫描；
5. 同名 Skill 显示页面内确认，确认后事务更新，失败恢复原版本。

默认限制为 ZIP 50 MB、解压或文件夹总量 200 MB、5,000 个文件、单文件 50 MB。上传安全合同见 [`../../docs/M11_OPENCLAW_FORMAL_SKILL_UPLOAD_ADMISSION.md`](../../docs/M11_OPENCLAW_FORMAL_SKILL_UPLOAD_ADMISSION.md)，最终单入口发布证据见 [`../../docs/M12_OPENCLAW_UNIFIED_SECURITY_CENTER_RELEASE.md`](../../docs/M12_OPENCLAW_UNIFIED_SECURITY_CENTER_RELEASE.md)。
