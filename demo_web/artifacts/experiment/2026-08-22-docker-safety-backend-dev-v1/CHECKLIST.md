# D2 Docker 安全执行后端检查表

- [x] 用户授权启动 Docker Desktop。
- [x] Docker Desktop 4.86.0 / Engine 29.7.2 已就绪，Linux/amd64。
- [x] 固定 Python 3.12-slim 镜像已在本机存在，不需要联网下载。
- [x] 预注册研究问题、假设、指标、安全停止条件和代码变更图。
- [ ] 配置拒绝浮动 tag、镜像拉取、privileged/host network/host PID 和 Docker Socket。
- [ ] 只允许固定单文件只读挂载和有界 tmpfs。
- [ ] create 后 inspect 安全门全部通过才 start。
- [ ] 自建 probe 验证非 root、capability=0、NoNewPrivs=1、只读根、输入只读和工作区可写。
- [ ] 网络模式 none、CPU/内存/PID/超时限制均有真实 inspect 证据。
- [ ] 成功、失败和超时清理路径均有测试，运行后容器残留 0。
- [ ] 动态专项测试和后端完整测试通过。
- [ ] 真实 D2 运行完成并生成 manifest、日志、指标、环境和哈希证据。
- [ ] 第三方/回归样本读取执行、互联网、GPU、云和静态决策变化均为 0。
