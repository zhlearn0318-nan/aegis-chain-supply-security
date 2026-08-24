# Aegis Chain 快速启动与运行时重建

> 本文只定义当前操作步骤；系统完成度与生产发布判断见 [`CURRENT_STATUS.md`](CURRENT_STATUS.md)。

本文面向首次拿到仓库的 Windows 使用者。仓库可以放在任意目录，不依赖开发者用户名、盘符或 Codex 私有路径。

## 1. 准备软件

静态审计需要：

- Windows 10/11 与 PowerShell 5.1 或 7；
- Git；
- Miniconda 或 Anaconda；
- Node.js（带 Corepack）或可直接使用的 `pnpm`。

管理员动态验证还需要 Docker Desktop，并启动 Linux 容器引擎。没有 Docker 时仍可使用静态审计。

## 2. 重建并核验 Cisco 运行时

在仓库根目录运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\bootstrap_runtimes.ps1"
```

脚本会：

1. 创建项目内的 `.runtime_skill`（Python 3.11）和 `.runtime_mcp313`（Python 3.13）；
2. 按带 SHA-256 的锁定依赖文件安装依赖；
3. 从 Cisco 官方仓库检出固定提交、构建 wheel 并以非 editable 方式安装；
4. 精确核对扫描器版本和命令入口。

MCP 运行时还会依次应用 `demo_web/backend/requirements.lock` 和 `runtime-security.lock`：前者锁定 Web 后端，后者覆盖共享 Cisco/Aegis 环境中已经确认的漏洞版本；安装后必须通过 `pip check`。

已经完整且版本正确的环境会复用；已存在但不完整或版本不符的目录不会被覆盖，脚本会停止并提示人工移开该目录。

仅核验现有环境：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\bootstrap_runtimes.ps1" -VerifyOnly
```

只重建一套环境可传入 `-Component Skill` 或 `-Component Mcp`。如命令未进入 `PATH`，可临时设置 `AEGIS_CONDA_COMMAND`、`AEGIS_GIT_COMMAND` 或 `AEGIS_PNPM_COMMAND` 指向对应程序。

离线重建可使用：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\bootstrap_runtimes.ps1" `
  -Offline `
  -WheelDirectory "<包含全部锁定依赖与Cisco wheel的目录>" `
  -SkillWheelSha256 "<审核清单中的64位SHA-256>" `
  -McpWheelSha256 "<审核清单中的64位SHA-256>"
```

离线目录必须事先包含两份 Cisco wheel 和锁定文件需要的全部依赖包；两个 Cisco wheel 还必须传入来自独立审核清单的 SHA-256，不允许仅凭文件名安装。仓库不会上传体积较大的 wheel 缓存。普通用户优先使用联网重建；联网模式始终从已验证的固定源码提交新建 wheel，不复用未验证的同名缓存。

## 3. 启动前预检

静态审计预检：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\preflight.ps1" -SkipDynamic
```

完整动态审计预检：

```powershell
$env:AEGIS_ADMIN_TOKEN = "请替换为至少16位且仅本次会话使用的随机令牌"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\preflight.ps1" -RequireDynamic
```

预检只读取 Docker 状态且使用 `pull=never` 语义，不会自动拉取镜像。需要机器可读结果时增加 `-Json`。

## 4. 一键启动演示平台

```powershell
Set-Location .\demo_web
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1"
```

启动脚本会自动执行预检、使用锁文件准备前端、完成生产构建，再启动后端。没有管理员令牌或 Docker 时，默认允许静态审计启动，并明确警告动态能力尚未就绪。

要求动态能力全部就绪才允许启动：

```powershell
$env:AEGIS_ADMIN_TOKEN = "请替换为至少16位且仅本次会话使用的随机令牌"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1" -RequireDynamic
```

如 8000 端口已被占用，可显式选择其他本机端口：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1" -Port 8765
```

常用地址：

- 页面：`http://127.0.0.1:8000`
- API 文档：`http://127.0.0.1:8000/docs`
- v1 健康检查：`http://127.0.0.1:8000/api/v1/health`

停止服务：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\stop_demo.ps1"
```

管理员令牌只放在当前进程环境中，不要写入源码、Markdown、截图或提交记录。

## 5. 运行测试与 Cisco 复现样例

完整后端测试：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\run_tests.ps1"
```

Cisco 防御性样例复现：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run_all.ps1"
```

依赖漏洞查询需要网络；Skill/MCP 的 YARA 与静态样例扫描不需要 API Key。

## 固定版本

- Cisco Skill Scanner：官方提交 `4dee90371890ff23e1b21ea974e02847eacaa464`，包版本 `2.0.13.dev3+g4dee90371`；
- Cisco MCP Scanner：官方提交 `51966cce214ae057e69c3a672307911f5026e255`，包版本 `4.8.2`；
- 前端包管理器：`pnpm@11.19.0`；直接依赖精确固定，`pnpm-lock.yaml` 保留完整性值，`pnpm-workspace.yaml` 对已知风险传递依赖设置覆盖和 24 小时最小发布年龄；
- Python 依赖：Cisco 锁、Web 后端锁和共享运行时安全覆盖锁中的版本及下载对象均由哈希约束。

两个 Cisco 上游项目当前均使用 Apache-2.0 许可证。本脚本默认在用户本机从官方固定提交构建，GitHub 仓库不重新分发大体积第三方 wheel。若最终作品包需要离线携带 wheel，应同时保留上游 LICENSE/NOTICE 与第三方组件清单。

当前 P0-1 已通过本机真实启动、路径无关检查和模拟不同 Windows 用户环境验证；真正的全新虚拟机从零复现仍属于后续 P0-5 发布验收，文档不会把模拟验证表述为已完成的洁净机验证。

## 7. 提交前自身供应链检查

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\audit_project_supply_chain.ps1" -WriteRepositoryArtifacts
```

成功时会输出 `PASS`，并更新根目录项目 SBOM 和第三方声明。漏洞数据库查询需要网络；无网络或审计器异常均不会降级为通过。P0-4 结果是时间截面，不能替代后续持续扫描。
