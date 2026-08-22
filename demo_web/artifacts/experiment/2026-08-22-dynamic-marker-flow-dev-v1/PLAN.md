# 动态 Marker 源到汇开发实验计划

- run id：`2026-08-22-dynamic-marker-flow-dev-v1`
- 实验等级：`auxiliary/dev`
- 静态基线：`2026-08-22-static-audit-regression600-v1`，只读且不做数值比较
- 数据：1 个仓库内自建、SHA-256 锁定的良性 fixture；外部/回归样本读取和执行均为 0
- 研究问题：能否在无 Docker、无互联网和最终决策不变的条件下，形成“假公文文件源→Base64→本机回环汇点”的脱敏 witness？
- 零假设：无法形成 witness，或发生原文泄露、越界、运行失败或决策变化。
- 备择假设：1/1 fixture 完成、3/3 事件检查、1 条 Base64 witness、关联状态 confirmed，负面安全指标和决策变化均为 0。
- 最小证据：Marker 四种编码和分片单元测试通过；受控 fixture 可运行。
- 扎实证据：专项测试、完整后端测试、实际运行产物和 SHA-256 清单全部通过。
- 停止条件：任何第三方样本被读取/执行、外网连接、工作区外写入、原始 Marker 进入报告或静态决策变化。
- 边界：结果只支持受控机制，不支持不可信代码沙箱或恶意检出率声明。

## 最小代码变更图

| 路径 | 变更 | 目的 |
|---|---|---|
| `backend/dynamic_audit/markers.py` | Marker 生成、编码与有界源到汇匹配 | 形成脱敏 witness |
| `backend/dynamic_audit/planning.py` | 静态 Finding 到 Trigger Plan 与独立关联 | 建立静态引导动态接口 |
| `backend/dynamic_audit/runner.py` | 回环汇点匹配和受控 Marker fixture | 真实验证文件读与网络汇点 |
| `tools/dynamic/fixtures/marker_file_to_loopback.py` | 良性自建 fixture | 模拟 Base64 外传机制 |
| `tools/dynamic/run_marker_flow_audit.py` | 可复现实验与证据导出 | 固化指标、环境、命令和哈希 |
| `backend/tests/test_dynamic_evidence.py` | 编码、分片、计划、关联和集成测试 | 防止机制漂移 |
