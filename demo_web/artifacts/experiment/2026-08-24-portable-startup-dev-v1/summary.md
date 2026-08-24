# P0-1 可移植启动实验摘要

本轮结论为 `supported_on_current_machine_and_simulated_user`。启动链已消除开发者个人 `pnpm` 绝对路径，改为脚本相对定位项目运行时，并在 PATH 中自动发现 pnpm 或 Corepack。

默认静态 preflight 必需失败数为 0。将 `USERPROFILE/LOCALAPPDATA/APPDATA` 切换到新的模拟用户树、从 PATH 移除 Codex pnpm 后，真实 Corepack pnpm 11.23.0 仍通过。项目也在 8765 端口完成预检、生产构建、启动、v1 健康检查和停止。

新增的 `bootstrap_runtimes.ps1` 固定 Cisco 官方仓库、提交、包版本、Python 版本和带哈希依赖锁；它不自动覆盖异常环境。本轮对现有环境做了 2/2 精确核验，没有为了测试而删除已可用环境。

验证结果为后端 `329 passed`、前端 `10 passed`、冻结离线安装与生产构建通过。检测规则和准入策略变化均为 0。

本轮不能替代全新 Windows 虚拟机的从零验收；后者保留为 P0-5 发布门。下一开发项按评委审查计划进入 P0-2：动态任务互斥、排队、重复提交保护和重启恢复。
