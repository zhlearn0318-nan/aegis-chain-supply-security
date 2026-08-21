# M3：Aegis Sensitive Flow v1 实现与开发集报告

日期：2026-08-21  
运行 ID：`2026-08-21-aegis-sensitive-flow-dev-v1`  
实验级别：`auxiliary/dev`  
结论：**开发集机制证据成立；尚未进行封存回归，不作最终泛化声明。**

## 1. 本轮解决的问题

原有 Network Context 能提示“同一个 Skill 里同时出现敏感来源和网络汇点”，但全部为 `INFO`。这种共现证据不能证明敏感值真的被发送，因此不能直接用于自动阻断。

本轮新增独立分析器 `aegis-sensitive-flow-v1`，只在静态分析能建立“敏感来源 → 变量传播 → 外部 payload 汇点”的明确链路时产生 `HIGH/CRITICAL` Finding。它不修改 Cisco 原始 Finding，也不改变已有 `aegis-static-v1` 规则，新增结果继续交给统一 YAML 准入策略裁决。

## 2. 已实现规则

| 规则 ID | 严重度 | 触发条件 | 门禁效果 |
|---|---|---|---|
| `AEGIS_CREDENTIAL_IN_OUTBOUND_PAYLOAD` | `CRITICAL` | 明确凭据环境变量或凭据文件内容，经变量传播进入 HTTP body/query、上传、消息、邮件或 socket payload | `BLOCK` |
| `AEGIS_SENSITIVE_DATA_TO_OUTBOUND_SINK` | `HIGH` | 整体环境变量集合或敏感业务文件内容，经变量传播进入同类外发 payload | `BLOCK` |

第一版覆盖 Python 与 JavaScript/TypeScript 源文件。Python 使用 AST 做有限的赋值传播、函数返回摘要和调用参数关联；JavaScript/TypeScript 使用受限语句与变量传播模式。分析只读取代码，不执行、导入或安装样本。

## 3. 误报保护

本轮专门保留以下正常场景：

- Token 仅进入 `Authorization` 等请求头，不进入 body/query；
- 敏感源和网络调用只在同一文件共现，但 payload 使用无关变量；
- 安全测试与 fixture 目录中的攻击示例；
- 无法证明变量传播的邻近线索继续留在 INFO Context，不自动升级。

Finding 只保存规则 ID、严重度、相对文件、行号和规范化证据代码；不保存凭据值、目标 URL、消息正文或样本代码。

## 4. 接入位置

```text
Cisco Skill Scanner Finding
          +
Aegis Static v1 Finding
          +
Aegis Sensitive Flow v1 Finding   ← 本轮新增，会参与门禁
          +
Network / Filesystem / Command Context Finding（INFO-only）
          ↓
统一 YAML 策略 → ALLOW / REVIEW / BLOCK / UNKNOWN
```

分析器已经接入真实 Skill 扫描编排和健康状态接口，不是仅用于离线实验的脚本。

## 5. 测试与开发集结果

### 5.1 自动测试

- Sensitive Flow 专项测试：`12 passed`；
- 完整后端测试：`154 passed`；
- 覆盖 Python/JavaScript 正例、正常鉴权反例、仅共现反例、测试夹具排除、Finding ID 稳定性和真实扫描编排接线。

### 5.2 120 条可见开发集配对评估

| 指标 | 结果 |
|---|---:|
| 开发集样本 | 120 |
| 新分析器命中样本 / Finding | 1 / 1 |
| 非正常样本决策升级 | 1 |
| 正常样本决策升级 | **0 / 50** |
| 正确控制样本决策变化 | **0 / 20** |
| Aegis Static v4 等价 | **120 / 120** |
| 样本哈希变化 | **0 / 120** |
| 回归集打开数 | **0 / 600** |
| Sensitive Flow 平均耗时 | 16.65 ms/条 |
| Sensitive Flow 最大耗时 | 149 ms/条 |

唯一新增命中为恶意开发样本 `case_03640`：分析器证明整体环境数据经变量与消息构造传播到邮件发送 payload，触发 `AEGIS_SENSITIVE_DATA_TO_OUTBOUND_SINK`，使既有结果从 `ALLOW` 变为 `BLOCK`。报告只记录规范化链路 `environment_collection → message_or_socket_send → exact_variable_flow`，不保留原始环境值、邮件内容或地址。

该结果满足预先固定的备择假设：至少补出 1 个非正常样本，且正常样本升级为 0。因此结果分类为 `supported_on_development_set`。

## 6. 如何复核

在 `demo_web` 目录运行：

```powershell
..\.runtime_mcp313\Scripts\python.exe -m pytest backend\tests\test_sensitive_flow.py -q --basetemp=artifacts\test_tmp\sensitive-flow
..\.runtime_mcp313\Scripts\python.exe -m pytest backend\tests -q --basetemp=artifacts\test_tmp\backend-all
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\run_sensitive_flow_development.py
```

完整证据位于：

- `artifacts/experiment/2026-08-21-aegis-sensitive-flow-dev-v1/PLAN.md`
- `artifacts/experiment/2026-08-21-aegis-sensitive-flow-dev-v1/CHECKLIST.md`
- `artifacts/experiment/2026-08-21-aegis-sensitive-flow-dev-v1/metrics.json`
- `artifacts/experiment/2026-08-21-aegis-sensitive-flow-dev-v1/evaluation_summary.json`
- `artifacts/experiment/2026-08-21-aegis-sensitive-flow-dev-v1/run_manifest.json`
- `artifacts/experiment/2026-08-21-aegis-sensitive-flow-dev-v1/per_case_sensitive_flow.jsonl`

评估器拒绝覆盖已经完成的运行产物，并在分析前后验证每条开发样本的 tree SHA-256。

## 7. 结论边界与剩余风险

可以陈述：

> 已实现敏感来源到外部 payload 的有限静态数据流关联，并在 120 条可见开发集上补出 1 条原先放行的恶意样本；50 条正常样本零升级，旧静态结果与样本哈希均保持不变。

暂时不能陈述：

- 已证明对未知 Skill 具有稳定召回率；
- 已完成全部数据外传检测；
- 已通过 600 条独立回归集；
- 已具备跨文件、框架级或运行时完整污点分析能力。

第一版仍是有界、路径不敏感分析：Python 主要覆盖顶层函数摘要，JavaScript/TypeScript 主要覆盖常见直接赋值；别名、复杂容器、类方法、跨文件调用、动态属性、反射和框架封装仍可能漏报。目标白名单和业务授权也尚未作为自动降级依据。

## 8. 下一步

按静态规则计划进入 E02：实现“不可信输入 → Shell/动态执行”的精确变量流。开发时继续保护固定可执行文件、参数数组和安全测试夹具；仍只使用可见开发集，600 条回归集保持封存。
