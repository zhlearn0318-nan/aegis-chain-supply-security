# CHECKLIST：Skill 动态沙箱真实 Docker 重复验收 v2

- [x] Docker Desktop 状态为 `running`
- [x] Docker Client/Server 均为 29.7.2
- [x] 关闭导致启动崩溃的 Docker Model Runner
- [x] 固定镜像 digest、OS 与架构一致
- [x] 5 个 fixture 的文件集合和 SHA-256 通过
- [x] 3 轮共 15 次容器执行完成
- [x] 决策正确 15/15
- [x] 良性误报 0
- [x] 危险漏报 0
- [x] 遥测缺失 0
- [x] 清理失败 0
- [x] 按后端标签查询容器残留 0
- [x] 第三方样本执行 0
- [x] GPU 使用 0
- [ ] Falco/eBPF 交叉证据（可选增强，不阻断默认后端）
- [ ] 第三方 Skill 试运行（需单独风险评估和更强隔离后再决定）
