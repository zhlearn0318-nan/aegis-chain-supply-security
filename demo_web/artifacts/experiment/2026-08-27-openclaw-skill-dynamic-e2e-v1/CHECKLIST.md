# CHECKLIST：OpenClaw Skill 动态准入真实 E2E v1

- [x] OpenClaw 2026.7.1-2 身份确认
- [x] Docker Engine 就绪
- [x] 新建独立 state/workspace/profile/temp
- [x] required 与无效模式配置通过 OpenClaw schema 校验
- [x] fixture 文件集合与 SHA-256 一致
- [x] 安全样本静态对照为 ALLOW
- [x] Shell 样本静态对照为 ALLOW
- [ ] 安全样本 required 动态安装成功
- [ ] Shell 样本由动态证据升级 BLOCK
- [x] 无效动态配置失败关闭
- [x] 两个阻断 slug 均无安装残留
- [x] 用户默认 workspace 无测试 slug
- [x] 输入源码哈希前后不变
- [ ] 准入审计链有效且证据完整（链有效，但 required 两例只有设施失败证据）
- [x] Docker 动态容器残留为 0
- [ ] 后端完整回归通过

结论：v1 如实冻结为失败。隔离 profile 未包含 Docker `desktop-linux` context，导致安全与 Shell 两例都失败关闭；修复转入 v2。
