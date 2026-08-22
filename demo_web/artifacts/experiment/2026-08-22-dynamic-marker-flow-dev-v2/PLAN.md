# 动态 Marker 源到汇开发实验 v2 计划

- run id：`2026-08-22-dynamic-marker-flow-dev-v2`
- 父运行：`2026-08-22-dynamic-marker-flow-dev-v1`，保留且不覆盖
- 变更：静动态 `confirmed` 必须同时满足运行完成、存在源到汇 witness、witness profile 属于静态 Trigger Plan。
- 不变：fixture、fixture SHA-256、网络/文件/进程边界、指标定义、静态基线和最终决策不变原则。
- 备择假设：计划内 `official_document` Marker 形成 1 条 Base64 witness 并得到 confirmed；计划外 Marker 反例只能得到 observed。
- 接受门：专项测试全部通过，1/1 fixture、3/3 事件、1 条计划内 witness、0 泄露、0 越界、0 决策变化；完整后端测试无回退。
- 边界：只支持自建良性 fixture 的机制结论，不支持恶意检出率和沙箱安全声明。
