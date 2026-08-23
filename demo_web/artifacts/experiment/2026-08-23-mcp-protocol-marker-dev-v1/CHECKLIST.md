# D3 MCP 协议调用与 Marker 证据闭环 v1 检查表

## 进行中

- [x] 选定受控 MCP stdio 协议闭环路线。
- [x] 核对静态回归、Marker v2 和 Docker v2 基线。
- [x] 查证 MCP 2025-06-18 生命周期、stdio 和 tools 规范。
- [x] 预登记研究问题、零假设、指标、停止与放弃条件。
- [x] 实现哈希锁定的自建 MCP fixture。

## 下一步

- [x] 实现独立 MCP Docker 配置与失败闭锁后端。
- [x] 实现协议转录验证、调用前后 Marker 对照和静动态关联。
- [x] 增加正常序列、非法参数、未知工具、脱敏和清理测试。
- [x] 执行专项冒烟测试：首次 2 passed / 10 setup errors（默认临时目录拒绝访问）；改用实验目录后 12 passed。
- [x] 执行真实 Docker 主运行：66/66 接受门通过。
- [x] 核验指标、日志、文件哈希与容器零残留。
- [x] 执行完整后端回归：308 passed。
- [x] 形成 MCP 协议与 Marker v1 实现报告。
- [x] 提交本地 `dynamic-audit-v1` 分支。

## 延后

- [ ] syscall/inotify/进程树等系统级遥测。
- [ ] 经审核的第三方 MCP Server 接入。
- [ ] 动态证据影响最终阻断策略（当前明确保持 `policy_effect=none`）。

## 阻塞

- [x] 无。

## 完成摘要

- [x] MCP 步骤 4/4，调用前 witness 0，调用后 witness 1，关联 `confirmed`。
- [x] 镜像 4/4、inspect 24/24、运行时 12/12、协议与证据 26/26，总计 66/66。
- [x] 协议错误、策略违规、超时、原始 Marker 泄漏、容器残留、第三方执行和决策变化均为 0。
- [x] 下一行动明确为 syscall、文件系统和进程级独立遥测。
