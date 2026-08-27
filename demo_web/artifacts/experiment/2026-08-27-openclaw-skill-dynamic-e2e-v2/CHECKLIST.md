# CHECKLIST：OpenClaw Skill 动态准入真实 E2E v2

- [x] v1 失败证据保持不变
- [x] 新 run id 与全新隔离运行目录
- [x] Docker context 只提供给可信 policy 进程
- [x] Cisco 扫描器仍使用合成 profile
- [x] Docker context 未挂载到目标容器
- [x] required 与无效模式配置校验通过
- [x] 安全与 Shell 静态对照均为 ALLOW
- [x] 安全 Skill 动态 ALLOW 并安装成功
- [x] Shell Skill 动态 CRITICAL 并阻断
- [x] 无效动态模式失败关闭
- [x] 阻断安装残留 0
- [x] 用户默认 workspace 测试 slug 0
- [x] 源码哈希变化 0
- [x] 审计链和三类审计证据通过
- [x] Docker 容器残留 0
- [x] 后端完整回归：418 passed，1 skipped
