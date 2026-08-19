# M1.1：统一安全结果契约

## 做了什么

- `backend/models.py`：定义 `Finding`、`ScanSummary`、`ScanJob`、严重度、任务状态和四态决策。
- `backend/policy.py`：把门禁逻辑从 API 文件中拆出；未知或厂商新增严重度返回 `UNKNOWN`，不能误放行为 `ALLOW`。
- `backend/normalizers.py`：Skill、MCP 和依赖扫描结果统一转换成经过 Pydantic 校验的 Finding。
- `backend/app.py`：新任务和数据库读写都通过 `ScanJob` 校验，并给旧历史记录补 `schema_version` 与 `summary.unknown`。

## 为什么先做这一层

后续自研规则、权威数据集、动态沙箱和统一平台接入都需要稳定的数据契约。如果直接把 Cisco 原始 JSON 暴露给前端或队友，上游字段一变，所有模块都会一起修改，也无法清晰区分“Cisco 发现”和“自研证据”。

## 验证结果

- 自动测试：16/16 通过。
- 高风险 Skill：仍为 `BLOCK`，4 条 Finding，1 条 CRITICAL。
- MCP 混合对象集：扫描完成并为 `BLOCK`，7 条 HIGH Finding。
- 两类新任务均返回 `schema_version: 1.0` 和 `unknown: 0`。

## 当前边界

为了保持 API 稳定，`app.py` 暂时保留旧函数作为兼容代码，但实际运行路径已切换到新模块。下一步将 subprocess 调用拆入 adapters，随后删除这些重复函数。
