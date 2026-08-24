# P0-1 可移植启动验收清单

- [x] 基线固定为 `3d98c8543bb5a323817566237d5f17b4b729dfc5`。
- [x] 未修改扫描规则、准入策略或动态安全边界。
- [x] 活动启动文件中开发者绝对路径命中数为 0。
- [x] 默认静态 preflight 必需失败数为 0。
- [x] 修改 `USERPROFILE/LOCALAPPDATA/APPDATA` 并移除 Codex pnpm 路径后，Corepack preflight 通过。
- [x] 固定 Cisco 来源、提交、包版本、Python 版本和带哈希依赖锁。
- [x] 已有运行时 `-VerifyOnly` 精确版本验证 2/2 通过。
- [x] `-RequireDynamic` 在缺少管理员令牌时失败闭锁。
- [x] 8765 端口真实启动、`/api/v1/health` 检查与停止通过。
- [x] 后端 `329 passed`。
- [x] 前端 `10 passed`、冻结离线安装和生产构建通过。
- [x] 证据、源文件哈希、声明边界和下一路由已固化。
- [ ] 全新 Windows 虚拟机从零重建（保留为 P0-5 发布验收）。
