# M3 静态审计 600 条密封回归评测协议

> 状态：已预注册，待开封执行  
> 协议版本：1.0  
> 固定日期：2026-08-22  
> 静态审计冻结提交：`f84927893a6bedcde4afa049a28c04be59316b73`

## 1. 目标与边界

本次评测回答一个限定问题：在同一批 600 条 SkillTrustBench v1.0 密封工程回归样本上，将当前 Aegis 静态审计层叠加到已冻结 Cisco Skill Scanner 结果后，是否改善三分类检测效果，且没有造成不可接受的恶意样本召回下降或正常样本误报增长。

这 600 条数据是从已使用过的 SkillTrustBench 全量数据中确定性抽取的工程回归集，不是独立外部盲测集。因此结果可以支持“版本回归验证”和“相对冻结 Cisco 基线的增强效果”，不能表述为对未知真实世界数据的无偏泛化性能。

## 2. 不可变输入

| 输入 | 固定值 |
| --- | --- |
| 回归划分 | `2026-08-15-skilltrustbench-dev120-regression600-v1` |
| 样本数 | 600（normal/suspicious/malicious 各 200） |
| 回归 JSONL SHA-256 | `8ee8745594cf2d7ef643cf95e61ccd88c420b42c540780dadb7320cbe7c90492` |
| 回归 ID SHA-256 | `cd83b4f4251b23701fdd98b6b9d3899777ca41f9d573d4fb502ce3307f0cc07d` |
| Cisco 父结果 SHA-256 | `15a9ec0cdb3b30d7d55d4a3f67e8a31b9f324f7724c46ede83ec07d5f79cd918` |
| 指标合同 SHA-256 | `d7c6fd64ffde14e50c1cd112a8923857b88dbcf4b1068600d75aa3650c4eb2ac` |
| 准入策略 SHA-256 | `010ca27b327e5098b11d7819563b40a607cac7698ac01019740557b8eaececf5` |

评测程序必须在读取 `regression_cases.jsonl` 内容前验证以上哈希及静态分析器源码哈希。任何不一致均终止开封。

## 3. 系统对照

- **Cisco 基线**：直接使用冻结父结果。`ALLOW/REVIEW/BLOCK/UNKNOWN` 分别映射为 `normal/suspicious/malicious/abstain`。
- **Aegis 增强系统**：仅对 Cisco 父扫描状态为 `completed` 的样本，将其紧凑 Cisco findings 与下列冻结静态分析器 findings 合并，再执行统一准入策略：Aegis Static、Sensitive Flow、Untrusted Exec Flow、Enterprise Controls、Static Coverage、Network Context、Filesystem Context、Command Context。
- Cisco 父扫描不是 `completed` 的样本，两套系统均保留为 `abstain`；Aegis 不替代厂商失败。
- 上下文层保持 INFO-only，但仍纳入完整集成链并记录，用于可解释性验证。

## 4. 安全与完整性约束

- 只读处理样本文本；禁止执行、导入、安装或联网获取样本内容。
- 每个可分析样本在分析前后计算目录树 SHA-256，必须与划分记录一致。
- 样本原文不写入输出；只保留规则 ID、严重度、分析器、相对位置和规范化证据代码。
- 分析器异常、目录缺失或树哈希不一致均产生增强系统 `abstain` 和显式失败记录，不静默删除。
- 一旦开封，不允许修改规则、分析器、策略、指标或本协议；任何后续修改必须建立新版本和新回归集。

## 5. 指标与统计方法

主指标为 `strict_macro_f1`，弃权按错误计入。同步报告：coverage、failure_rate、covered_macro_f1、malicious_recall/FNR、non_normal_recall、normal_fpr、T01-T09 recall、混淆矩阵和延迟。

延迟分开报告：冻结 Cisco 延迟、Aegis 增量延迟，以及两者相加得到的“估算顺序执行总延迟”；后者不是本轮重新实测的 Cisco 端到端时间。

配对统计方法固定为：

1. 对两系统逐样本正确/错误状态执行双侧精确 McNemar（二项）检验；
2. 使用固定随机种子 `20260822`、10,000 次成对自助重采样，估计严格宏平均 F1 差值的 95% 百分位置信区间。

## 6. 预注册判定规则

首先满足可比较门槛：恰好 600 条且三类各 200；输入哈希全部匹配；可分析样本零树哈希不一致；零新增增强分析失败；结果 ID 完整唯一；评测前后输入未改变。否则结论为 `not_comparable`。

在可比较前提下：

- `strongly_supported`：严格宏平均 F1 差值大于 0，95% CI 下界大于 0，恶意召回不下降，正常误报率增幅不超过 0.02。
- `supported_with_tradeoff`：严格宏平均 F1 上升且恶意召回不下降，但未同时满足强支持的置信区间或 0.02 误报约束。
- `refuted`：严格宏平均 F1 下降，或恶意召回下降，或正常误报率增幅超过 0.05。
- `inconclusive`：其余情况，包括点估计持平或统计证据不足。

发生条件重叠时按 `not_comparable`、`strongly_supported`、`refuted`、`supported_with_tradeoff`、`inconclusive` 的顺序判定。

`normal_fpr` 的 0.02 对应本回归集最多净增加 4/200 个正常误报；0.05 对应超过 10/200 个。

## 7. 输出

固定输出目录：`demo_web/artifacts/experiment/2026-08-22-static-audit-regression600-v1/`。

至少生成：逐样本结果、两套指标、指标差值、统计检验、错误切片、规则命中摘要、评测结论、运行日志、运行清单和独立验证结果。运行目录不可覆盖；失败后保留证据，重跑必须使用新的 run ID。

## 8. 开封纪律

在评测器单元测试、合成数据指标测试和只验证哈希的预检全部通过前，不读取回归 JSONL 内容。首次正式读取的时间写入 `seal_opened.json` 并立即落盘。正式运行完成后只做结果解释和工程修复；本回归集不再用于调规则。
