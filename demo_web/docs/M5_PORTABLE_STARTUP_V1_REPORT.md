# M5 P0-1 可移植启动与换机复现报告

## 1. 问题与目标

改造前的 `start_demo.ps1` 直接引用开发者个人 Codex 目录中的 `pnpm.cmd`。这会导致仓库在队友电脑、评委机或新用户路径下无法启动，且缺失组件时只能得到难理解的软件异常。

本轮 P0-1 的目标是完成三件事：

1. 启动不依赖个人用户名、盘符或 Codex 私有路径；
2. 启动前能区分“静态必需条件”和“动态可选/强制条件”；
3. 项目运行时缺失时，可从 Cisco 官方固定提交重建，而不是手工猜测安装。

## 2. 完成的开发

| 模块 | 完成内容 | 安全/工程价值 |
| --- | --- | --- |
| 共享发现 | 自动查找 pnpm、Corepack 和 Docker CLI，支持显式环境变量覆盖 | 消除个人绝对路径，失败点可解释 |
| Preflight | 检查 Cisco 精确版本、FastAPI、策略加载/哈希、锁文件、写权限、令牌、Docker 和固定镜像 | 支持人可读表格和 JSON；强制动态条件失败闭锁 |
| 一键启动 | 启动前预检，锁文件安装，生产构建，v1 health，可指定端口 | 避免浮动安装，端口冲突不需要杀死其他服务 |
| 运行时重建 | 固定 Cisco URL/提交/版本、Python 3.11/3.13、Rust 1.96、哈希锁和非 editable wheel | 供应链来源可追溯；异常环境不自动覆盖 |
| 回归测试 | 个人路径、锁定提交、Corepack 异用户发现、动态失败闭锁 | 防止后续修改把硬编码或误放行带回系统 |

## 3. 验证结果

| 验收项 | 结果 |
| --- | ---: |
| 活动启动文件个人绝对路径命中 | 0 |
| 默认静态 preflight 必需失败 | 0 |
| 模拟异用户 preflight 必需失败 | 0 |
| Cisco 现有运行时精确核验 | 2/2 |
| 真实启动/v1 health/停止 | 3/3 |
| 可移植专项测试 | 5 passed |
| 后端完整测试 | 329 passed |
| 前端测试 | 10 passed |
| 冻结离线安装/生产构建 | 通过/通过 |
| 检测规则/策略变化 | 0/0 |

异用户验证不是仅修改一个字符串：实验同时改变 `USERPROFILE`、`LOCALAPPDATA` 和 `APPDATA`，PATH 仅保留 Windows 与 Node.js，确认 Codex pnpm 路径不存在，然后由真实 Corepack 首次准备并运行固定的 pnpm 11.23.0。

## 4. 如何使用

从仓库根目录开始：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\bootstrap_runtimes.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\preflight.ps1" -SkipDynamic
Set-Location .\demo_web
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1"
```

需要强制动态能力时，设置至少 16 位的临时 `AEGIS_ADMIN_TOKEN`，启动 Docker Desktop，再使用 `-RequireDynamic`。详细操作见根目录 `QUICKSTART.md`。

## 5. 可声明边界

可以声明：当前启动代码已消除开发者个人路径；当前机器和模拟新用户环境可复现；现有 Cisco 环境符合锁定版本；缺少强制动态条件会失败闭锁。

暂时不能声明：已在独立全新 Windows 机器完成从零重建；已实现生产级高可用；已完成动态任务并发与崩溃恢复。

## 6. 下一步

按 M5 评委与工程审查顺序，下一个开发项是 P0-2：

- 动态任务全局互斥和有界排队；
- 重复提交幂等保护；
- 服务重启后对 `queued/running` 任务做明确恢复或失败收敛；
- 不改变已冻结的静态准入决策。

本轮详细可复核证据位于 `artifacts/experiment/2026-08-24-portable-startup-dev-v1/`。
