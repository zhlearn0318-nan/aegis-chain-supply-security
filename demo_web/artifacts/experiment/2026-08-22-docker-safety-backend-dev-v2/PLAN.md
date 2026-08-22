# D2 Docker 安全执行后端开发实验 v2 计划

- run id：`2026-08-22-docker-safety-backend-dev-v2`
- 父运行：`2026-08-22-docker-safety-backend-dev-v1`，保留且不覆盖
- 变更：兼容 Docker `ApiVersion/APIVersion` 字段；增加成功、非法 ID 和启动超时清理测试。
- 不变：镜像 digest/ID、自建 fixture SHA-256、40 个安全门、网络 none、只读根、非 root、资源限制、无 Docker Socket、无第三方样本和决策不变原则。
- 接受门：Engine API 版本准确；4/4 镜像、24/24 inspect、12/12 运行门通过；成功运行和超时模拟均清理容器；专项/完整测试通过。
- 声明边界：只支持当前 Docker 配置与自建 probe 的机制结论，不支持容器逃逸抵抗或第三方样本安全结论。
