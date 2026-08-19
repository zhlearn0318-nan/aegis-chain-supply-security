# M1.3：YAML 准入策略与策略追踪

> 完成日期：2026-08-10  
> 状态：已完成并通过自动化测试与三类真实回归  
> 新结果契约：`1.1`  
> 默认策略：`aegis-chain-local-default@1.0.0`

## 1. 本次目标

将 M1.2 中硬编码的严重度门禁迁移为经过严格校验的本地 YAML，同时保持默认决策完全等价。每个新扫描结果必须能回答：使用了哪个策略版本、命中了哪条规则、依据哪些 Finding、为什么得到该决策。

本次没有改变 Cisco 扫描器、测试样本、标签、风险严重度或准入阈值，因此不属于检测性能实验。

## 2. 默认策略

策略文件为 `config/admission_policy.yaml`：

```yaml
schema_version: "1.0"
policy_id: "aegis-chain-local-default"
version: "1.0.0"

decision:
  block_severities: [CRITICAL, HIGH]
  review_severities: [MEDIUM, LOW]
  allow_severities: [INFO, SAFE]
  fail_closed: true
```

加载器会拒绝以下配置：

- block、review、allow 集合发生重叠；
- 没有完整覆盖 `SAFE` 至 `CRITICAL`；
- 将 `UNKNOWN` 放入普通严重度集合；
- 设置 `fail_closed: false`；
- YAML 语法、编码或字段模型无效。

当前 YAML 只管理严重度门禁。敏感能力、禁用行为与允许域名尚未实现，不能在汇报中表述为已完成。

## 3. 新增结果字段

新任务使用 schema `1.1`，增加：

```json
{
  "policy_trace": {
    "policy_id": "aegis-chain-local-default",
    "policy_version": "1.0.0",
    "rule_id": "POLICY_BLOCK_SEVERITY",
    "reason": "命中阻断严重度：CRITICAL 1 条。",
    "matched_severities": ["CRITICAL"],
    "matched_finding_ids": ["DATA_EXFIL_HTTP_POST_example"],
    "fail_closed": true
  }
}
```

规则编号：

| 规则 | 含义 |
|---|---|
| `POLICY_ALLOW` | 扫描成功，发现项均在允许集合 |
| `POLICY_REVIEW_SEVERITY` | 命中 LOW 或 MEDIUM，需要人工复核 |
| `POLICY_BLOCK_SEVERITY` | 命中 HIGH 或 CRITICAL，直接阻断 |
| `POLICY_UNKNOWN_SEVERITY` | 存在未知严重度，失败闭锁 |
| `POLICY_CONFIGURATION_ERROR` | YAML 或策略模型无效 |
| `SCAN_TIMEOUT` | 外部扫描器超时 |
| `SCAN_EXECUTION_FAILED` | 外部扫描或归一化发生其他错误 |

Markdown 导出报告也会包含策略 ID、版本、命中规则和判定原因。

## 4. 向后兼容

- 新任务写入 schema `1.1` 和完整 `policy_trace`；
- 旧 schema `1.0` 记录保持原版本，不伪造升级；
- 旧记录缺少策略信息时补充 `unresolved / PENDING_SCAN`；
- 当前 `/api` 路径不变，新增字段为加法变更；
- 统一平台应容忍未来新增字段，并读取 `schema_version`。

## 5. 修改文件

| 文件 | 作用 |
|---|---|
| `config/admission_policy.yaml` | 默认策略 |
| `backend/policy.py` | YAML 加载、校验、策略评估与失败追踪 |
| `backend/models.py` | schema `1.1` 与 `PolicyTrace` |
| `backend/app.py` | 统一完成路径、失败规则、健康状态和报告导出 |
| `backend/normalizers.py` | 保证重复依赖漏洞的 Finding ID 唯一 |
| `backend/tests/test_policy.py` | 策略与失败闭锁测试 |
| `backend/tests/test_contract.py` | 旧记录兼容与依赖 ID 测试 |

## 6. 验证结果

自动化测试：

```text
45 passed in 0.49s
```

真实回归：

| 类型 | 任务 ID | 结果 | 唯一 ID | 策略规则 |
|---|---|---|---:|---|
| Skill | `0925421dc4e14011b8c07899c131dab6` | BLOCK；4 findings；1 CRITICAL | 4/4 | `POLICY_BLOCK_SEVERITY` |
| MCP | `31122f58c01b407ab53da1b8a7155836` | BLOCK；7 HIGH | 7/7 | `POLICY_BLOCK_SEVERITY` |
| 依赖 | `47788213766a4901abb233ccea5cddfd` | BLOCK；14 HIGH | 14/14 | `POLICY_BLOCK_SEVERITY` |

三类制品 SHA-256、风险数量和决策均与 M1.2 相同。完整 manifest、结果和运行记录位于 `artifacts/experiment/2026-08-10-m1-3-policy-config/`。

## 7. 后续进展与下一步

`/api/v1` 已于 2026-08-10 完成：包含版本化响应模型、机器可读错误结构、HTTP 202 异步创建、旧 `/api` 兼容和契约测试，详见 `docs/API_V1_CONTRACT.md`。

下一步将 `policy_trace` 和 v1 错误状态展示到前端，然后进入 SkillTrustBench 数据适配。
