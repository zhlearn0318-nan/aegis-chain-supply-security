# Aegis Admission UI for OpenClaw

该插件使用 OpenClaw 官方 Control UI 插件页机制，在左侧导航增加“Aegis 准入、Aegis 报告、Aegis 审计、Aegis 规则、Aegis MCP”五个页面。准入页只用于固定的现场演示样本，不提供任意文件上传或任意路径安装；管理页调用项目内安全引擎并保留最小化审计。

## 安装

在项目根目录执行：

```powershell
openclaw plugins install --link .\demo_web\openclaw_plugin\aegis-admission-ui
openclaw gateway restart
```

推荐在新 Windows 环境直接双击仓库根目录 `Install_Aegis_OpenClaw_Final.cmd`，由安装器完成固定版本、运行时、Docker、策略、插件、Gateway 和预检。

刷新 OpenClaw Web 控制台，在左侧选择“Aegis 准入”。也可以直接访问：

```text
http://127.0.0.1:18789/plugin?plugin=aegis-admission-ui&id=admission
```

## 运行要求

- OpenClaw `security.installPolicy` 已启用且目标包含 `skill` 与 `plugin`；
- `AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY=required`；
- Docker Desktop Linux Engine 可用；
- 项目保留固定版 SkillTrustBench 样本和审计运行时。

MCP 配置准入通过“Aegis MCP”页执行；放行时使用 OpenClaw 官方 `mcp set` 写入并用 `mcp show` 复核，阻断时不修改配置。

## 固定演示结果

- `case_00906`：预期 `ALLOW`，Docker 隔离试运行清洁，安装为 `aegis-web-safe-demo`；
- `case_01084`：预期 `BLOCK`，动态执行 0 次，不生成 `aegis-web-malicious-demo`。
