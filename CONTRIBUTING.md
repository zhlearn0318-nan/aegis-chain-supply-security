# Aegis Chain 团队协作与开发指南

本文面向需要克隆、运行和修改 Aegis Chain 的队友。当前协作主线是 `main`；`v0.1` 是不可改写的历史比赛标签，当前能力与限制以 [`CURRENT_STATUS.md`](CURRENT_STATUS.md) 为准。

## 1. 推荐协作流程

首次克隆：

```powershell
git clone https://github.com/zhlearn0318-nan/aegis-chain-supply-security.git
Set-Location .\aegis-chain-supply-security
git switch main
```

开始开发前同步主线并创建功能分支：

```powershell
git pull --ff-only origin main
git switch -c feature/<简短功能名>
```

完成后先运行对应测试，再提交和发起合并。不要在功能分支中提交本机运行环境、下载的数据集、扫描缓存、日志、数据库或密钥。

建议提交前缀：

- `feat:` 新功能；
- `fix:` 缺陷修复；
- `test:` 测试或评测；
- `docs:` 文档；
- `chore:` 构建、依赖或整理。

## 2. 开发环境

当前正式支持 Windows 10/11。完整动态审计需要 Git、Node.js、Miniconda/Anaconda、Docker Desktop Linux Engine、Ollama 和 OpenClaw。根目录安装器可通过 Windows Package Manager 补齐缺失软件：

```text
Install_Aegis_OpenClaw_Final.cmd
```

只开发静态后端或阅读代码时，可先运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\bootstrap_runtimes.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\preflight.ps1" -SkipDynamic
```

运行时由锁文件和固定上游提交重建，不上传到 GitHub，也不应在队员之间压缩传递。

## 3. 模块与修改入口

| 想修改的内容 | 主要目录 | 必须同步检查 |
| --- | --- | --- |
| Skill/MCP/API 后端 | `demo_web/backend/` | `demo_web/backend/tests/`、API 契约 |
| 静态规则与策略 | `demo_web/backend/analyzers/`、`demo_web/config/` | 规则注册表、开发/回归集、决策边界 |
| Docker 动态审计 | `demo_web/backend/dynamic_audit/`、`demo_web/tools/dynamic/` | 镜像/运行器哈希、安全门、三轮证据 |
| 独立 React 页面 | `demo_web/frontend/` | 前端测试和生产构建 |
| OpenClaw 安全中心 | `demo_web/openclaw_plugin/aegis-admission-ui/` | 插件 Node 测试、Gateway 重启、浏览器验证 |
| OpenClaw 安装准入 | `demo_web/backend/openclaw_install_policy.py`、`install_openclaw_final.ps1` | 安全/恶意样本、失败关闭、事务回滚 |
| 数据集与评测 | `demo_web/tools/datasets/`、`demo_web/tools/evaluation/` | 固定提交、哈希、标签隔离、冻结合同 |
| 状态和汇报材料 | `CURRENT_STATUS.md`、`demo_web/docs/` | 不覆盖历史证据，不夸大生产能力 |

## 4. 常用开发命令

后端完整测试：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\run_tests.ps1"
```

只运行后端测试：

```powershell
.\.runtime_mcp313\Scripts\python.exe -m pytest demo_web\backend\tests -q
```

OpenClaw 插件测试：

```powershell
Push-Location .\demo_web\openclaw_plugin\aegis-admission-ui
try { npm test } finally { Pop-Location }
```

独立前端测试和构建：

```powershell
Push-Location .\demo_web\frontend
try {
    pnpm test
    if ($LASTEXITCODE -eq 0) { pnpm run build }
} finally { Pop-Location }
```

完整预检：

```powershell
$env:AEGIS_ADMIN_TOKEN = ([guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N"))
try {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\preflight.ps1" -RequireDynamic
} finally {
    $env:AEGIS_ADMIN_TOKEN = $null
}
```

## 5. OpenClaw 插件开发

插件目录是系统正式界面的源码：

```text
demo_web/openclaw_plugin/aegis-admission-ui/
```

主要文件：

- `index.js`：插件注册、HTTP 路由、Python 安全引擎调用和安装动作；
- `security_center_page.js`：安全总览；
- `admission_page.js`：ZIP/文件夹上传、扫描、动态日志和安装；
- `admin_pages.js`：报告、审计、规则和 MCP 页面；
- `security_center_nav.js`：安全中心内部导航；
- `openclaw.plugin.json`、`package.json`：插件元数据和兼容版本。

重新链接插件：

```powershell
& "$env:APPDATA\npm\openclaw.cmd" plugins install --link ".\demo_web\openclaw_plugin\aegis-admission-ui"
& "$env:APPDATA\npm\openclaw.cmd" plugins enable aegis-admission-ui
& "$env:APPDATA\npm\openclaw.cmd" gateway restart
```

日常修改由于是链接安装，通常只需重启 Gateway。打开：

```text
http://127.0.0.1:18789/plugin?plugin=aegis-admission-ui&id=admission
```

不要绕过 OpenClaw 的安装策略直接向 Skill 安装目录复制文件，这会破坏准入闭环和审计证据。

## 6. 不进入 GitHub 的内容

以下内容由 `.gitignore` 排除：

- `.runtime_*`、`.venv*`、Conda 环境和包缓存；
- `datasets/`、`third_party/` 下载副本和大规模原始扫描结果；
- `node_modules/`、前端构建产物和临时测试目录；
- `demo_web/data/` 中的 SQLite、审计记录和自定义规则运行态；
- 日志、PID、本机 Docker/OpenClaw 配置；
- `.env`、Token、API Key、私钥和凭据文件。

允许提交的是可复现程序、固定配置、依赖锁、少量防御性 fixture、脱敏指标和精选证据。真实密钥只能通过当前进程环境变量提供。

## 7. 修改规则时的约束

1. 先在开发集上定位缺口，不使用冻结 test 结果直接调参；
2. 新规则必须有规则 ID、风险解释、命中证据、严重度与目标范围；
3. 同时加入良性对照和恶意/风险案例；
4. 运行相关专项测试和完整回归；
5. 更新规则注册表、状态文档和对应实验报告；
6. 动态 ALLOW 不得自动覆盖静态 HIGH/BLOCK，除非另行评审并修改正式策略合同。

## 8. 提交前检查

至少确认：

- `git diff --check` 无空白错误；
- 后端、插件和受影响前端测试通过；
- 没有本机绝对用户路径、真实 Token、API Key、私钥或数据库；
- 新依赖已精确锁定并更新 `THIRD_PARTY_NOTICES.md` / `PROJECT_SBOM.cdx.json`；
- README、`CURRENT_STATUS.md` 与实际测试数字一致；
- `git status --short` 中的每个文件都属于本次修改。

安全边界和漏洞报告方式见 [`SECURITY.md`](SECURITY.md)，系统当前可信结论见 [`CURRENT_STATUS.md`](CURRENT_STATUS.md)。
