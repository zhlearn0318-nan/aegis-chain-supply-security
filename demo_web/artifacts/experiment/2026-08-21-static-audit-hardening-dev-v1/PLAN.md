# Static audit hardening development plan

## 1. Map link

- parent_map_node: `2026-08-21-static-audit-dev-freeze-v5`
- loop_id: `static-audit-hardening-v1`
- node_objective: 修复四个会削弱静态审计可信度的关键缺口。
- node_deliverable: 加固代码、对抗测试、v6 冻结证据和本地提交。
- success_condition: 全部加固门禁、248+ 后端测试、9 个前端测试和生产构建通过，用户上传的 MCP 边界不能自我放行，600 条回归集仍未打开。
- abandonment_condition: 修复必须改变封存回归集或依赖执行第三方不可信代码。
- next_on_success: 一次性运行 600 条封存回归集。
- next_on_failure: 保留失败证据并建立新的加固版本，不覆盖本轮。

## 2. Objective

- run id: `2026-08-21-static-audit-hardening-dev-v1`
- selected idea: 将文本或目录名从“安全豁免条件”降为上下文，只接受机器可读边界；同时限制 ZIP 总展开量并对厂商 Finding 做统一最小化留存。
- user requirements: 暂不处理 PPT/视频，继续完成静态审计下一步。
- non-negotiable constraints: 不读取或运行 600 条封存回归集，不执行第三方 Skill，不修改 v5 基线产物。
- research question: 四项加固能否堵住已知绕过与泄露路径，同时保持现有开发链路可用？
- null hypothesis: 加固无法稳定阻断绕过，或引入不可接受的正常样本决策变化。
- alternative hypothesis: 加固测试全部通过，正常结构化控制仍可 ALLOW，文本自声明和测试目录代码至少进入 REVIEW。

## 3. Baseline and comparability

- baseline id: commit `c8e8f960775fff46f2206d6794b874e8fea39375`
- baseline variant: `static-audit-v1` / freeze v5
- dataset / split: 现有单元与微用例、120 条可见开发集；600 条回归集保持封存。
- primary metrics: 后端/前端测试通过数、四项加固门禁、开发集正常决策升级数、回归打开数。
- required metric keys: `backend_passed`, `frontend_passed`, `build_pass`, `hardening_gates`, `normal_upgrades`, `sealed_regression_opened`。
- comparability risks: MCP 安全对照从自然语言边界迁移为机器可读边界；测试目录 Finding 严重度固定为 MEDIUM，避免目录名直接造成 BLOCK。

## 4. Code translation plan

| Path | Planned change | Why | Risk |
|---|---|---|---|
| `backend/analyzers/mcp_policy.py` | 区分上传自声明与平台可信 sidecar | 防止文字或上传字段自我放行 | 安全对照需由受信任调用方注入 |
| `backend/analyzers/{sensitive_flow,untrusted_exec_flow,enterprise_controls}.py` | 不再跳过测试目录，命中降为 MEDIUM | 消除目录名逃逸 | 可能增加 REVIEW |
| `backend/analyzers/static_coverage.py` | 单独计数测试上下文 | 避免“已检查”表述过强 | 仅证据字段变化 |
| `backend/app.py` | 累计展开量、压缩比、特殊项和流式解压限制 | 防 ZIP bomb | 过严限制合法大包 |
| `backend/normalizers.py` | 厂商证据哈希化、固定描述、确定性 ID | 防凭据和提示内容落盘 | 报告原文减少 |
| `backend/tests/*` | 新增正反和绕过测试 | 固化安全语义 | 无 |
| `tools/evaluation/freeze_static_audit_development.py` | 生成 v6 并加入加固门禁 | 形成可复核证据 | 真实工具需可用 |

## 5. Execution design

- experiment tier: `auxiliary/dev`
- minimum: 聚焦测试通过且四个漏洞均有反例测试。
- solid: 全量测试、可见开发评估、真实四类冒烟和 v6 冻结通过。
- maximum: 封存回归；本轮明确不执行。
- smoke: 先运行新增测试文件。
- full run: 后端全量、前端测试/构建、五个开发评估脚本、v6 冻结。
- expected outputs: 本目录日志/指标/总结，以及 `artifacts/freeze/2026-08-22-static-audit-dev-freeze-v8/`。
- stop condition: 任一关键加固门禁失败或发现回归集被读取。

## 6. Runtime and recovery

- expected budget: CPU-only，分钟级。
- logs: `artifacts/experiment/2026-08-21-static-audit-hardening-dev-v1/`。
- fallback: 若厂商真实冒烟受外部环境影响，记录为外部依赖失败，不伪造通过；确定性单元测试仍保留。
- checklist: `CHECKLIST.md`

## 7. Revision log

| Time | Change | Reason | Impact |
|---|---|---|---|
| 2026-08-21 | 锁定四项加固与 v6 契约 | 用户授权 | v5 基线只读；600 条回归保持封存 |
| 2026-08-22 | 完成开发验证并生成 v6 | 全部预设门禁通过 | 未改变回归封存边界；结论限于开发证据 |
| 2026-08-22 | v6 后设计复核升级为可信 sidecar，建立 v7 | 上传字段仍是被审对象自声明 | 新增一个一般化反例；v6 保留但不作为最终候选 |
| 2026-08-22 | 统一换行并建立 v8 | Git LF 规范化会使 v7 工作树哈希不可复现 | 机械格式修复；功能、规则和评价口径不变 |
