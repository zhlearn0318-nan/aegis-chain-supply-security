# D3-B MCP 内核辅助遥测 v1 检查表

## 已完成

- [x] D3-A MCP 协议与 Marker v1 已冻结并提交。
- [x] 固定镜像中核验 `strace=False`。
- [x] 拒绝联网安装或放宽容器权限。
- [x] 预登记研究问题、对照、指标和停止条件。

## 进行中

- [x] 实现 inotify `OPEN/ACCESS/CLOSE_NOWRITE` 观测。
- [x] 实现 procfs 父子进程和目标 fd 独立观测。

## 下一步

- [x] 增加脱敏、缺失事件和父实验不退化测试：MCP 专项 13 passed，动态专项 51 passed。
- [x] 执行真实 Docker 遥测运行：82/82。
- [x] 独立核验容器残留、证据哈希和原始值泄漏：均为 0。
- [x] 完整后端回归：309 passed。
- [x] 形成 D3-B 内核辅助遥测报告。
- [ ] 本地提交。

## 延后

- [ ] 固定离线 strace 镜像与系统调用参数级追踪。
- [ ] eBPF/ETW 等更高权限遥测。
- [ ] 第三方样本执行。

## 完成摘要

- [x] inotify OPEN/ACCESS/CLOSE 3/3。
- [x] procfs 父子关系、目标 fd 2/2，fd 观察 47 次。
- [x] 独立文件读取确认 1。
- [x] 遥测错误、原始 PID/命令行/Marker 泄漏、容器残留和决策变化均为 0。
- [x] 下一步为 Skill 运行时全目录闭包与新内容提升。
