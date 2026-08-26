# OpenClaw E2E v1 检查表

- [x] 使用独立 state dir。
- [x] 发现并修正 workspace 未隔离问题。
- [x] 用户原工作区测试目录可恢复移出，残留 0。
- [x] 稳定版配置校验通过。
- [x] 安全 Skill 安装成功。
- [x] 恶意 Skill 阻断且无残留。
- [x] 稳定版原始 warn 失败关闭。
- [x] REVIEW 兼容模式阻断且无残留。
- [x] 策略 ACL/可信目录错误失败关闭。
- [x] Beta 包来源与 SHA-512 核验。
- [x] Beta 独立安装，不修改全局版本。
- [x] Beta Windows ACL 上游问题如实记录。
- [x] 后端完整 `386 passed`。
- [ ] 新版可确认 warn 流程通过。
- [ ] `doctor --deep` 安装策略项全绿。
