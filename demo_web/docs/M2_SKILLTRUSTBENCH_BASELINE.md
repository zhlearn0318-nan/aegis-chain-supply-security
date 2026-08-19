# M2 SkillTrustBench × Cisco 静态基线报告

> 运行日期：2026-08-10  
> 数据：SkillTrustBench v1.0 audited refresh 固定 90 条 pilot  
> 扫描器：Cisco Skill Scanner `2.0.13.dev3+g4dee90371`  
> 结论：`accepted_with_caveats`，可作为自研增量的只读对照，不代表最终系统成绩

## 做了什么

1. 在运行前固定数据 revision、90 条 case ID、标签映射和指标契约。
2. 先用 5 条 smoke 验证批量扫描、失败闭锁、结果脱敏和样本 hash。
3. 使用相同命令顺序扫描全部 90 条，不修改 Cisco 规则或 Aegis 策略。
4. 每条扫描前后复核 case tree hash；原始 Cisco JSON 在临时目录使用后删除。
5. 输出逐样本脱敏结果、混淆矩阵、FP/FN、全部分类错误、指标和失败诊断。

## 结果

| 指标 | 数值 | 正确解释 |
|---|---:|---|
| 处理样本 | 90/90 | 每条都有 completed 或失败闭锁终态 |
| coverage | 98.89% | 89 条获得非 abstain 预测 |
| failure rate | 1.11% | 1 条 Cisco 严格解析失败 |
| strict macro F1 | 0.5114 | 主三分类指标，abstain 计错 |
| supplementary accuracy | 54.44% | 辅助指标，不单独宣传 |
| malicious recall | 80.00% | 30 条 malicious 中 24 条判为 malicious |
| malicious FNR | 20.00% | 6 条 malicious 未判为 malicious |
| non-normal recall | 78.33% | suspicious/malicious 被判为 non-normal 的比例 |
| normal FPR | 33.33% | 30 条 normal 中 10 条被误报 |
| 中位/P95 耗时 | 3935/4226 ms | 单机顺序静态扫描 |

混淆矩阵：

| 真值 \ 预测 | normal | suspicious | malicious | abstain |
|---|---:|---:|---:|---:|
| normal | 20 | 7 | 3 | 0 |
| suspicious | 9 | 5 | 15 | 1 |
| malicious | 3 | 3 | 24 | 0 |

三分类的主要问题不是“完全检不出恶意”，而是边界粗糙：suspicious 只有 5/30 被精确分到 suspicious，15 条被升级为 malicious，9 条降为 normal；normal 误报率也达到 33.33%。

## 风险类型

T01–T09 的召回分别为：

```text
75.00%, 100.00%, 100.00%, 75.61%, 77.27%,
100.00%, 100.00%, 75.00%, 65.52%
```

T02、T06、T07 的 support 只有 2、2、1，不能据此宣传 100%。样本较多且相对明显的短板是 T09，其次是 T01、T04、T05。

## 唯一扫描失败

`case_02187` 的 UTF-8、文件结构和 PyYAML frontmatter 均正常，但 Cisco 使用的 `python-frontmatter` 严格解析路径返回 `ScannerError`。本项目将它保留为 `UNKNOWN/abstain`，没有使用 `--lenient` 重跑后覆盖主结果。

## 安全验证

- 90/90 样本 tree hash 前后一致；
- 只观察到 `static_analyzer / bytecode / pipeline`；
- LLM、VirusTotal、AI Defense、behavioral 未启用；
- 外部分析器 API key 不进入扫描子进程；
- 实验目录不含 evidence、description、remediation、snippet 或原始报告；
- 当前自动测试：`67 passed`。

## 能说与不能说

可以说：Cisco 静态底座在固定 90 条 pilot 上 malicious recall 为 80%，但 normal FPR 为 33.33%，三分类 macro F1 为 0.5114；这为自研改进提供了可复现对照。

不能说：系统最终准确率为 54.44%；Cisco 已覆盖所有攻击；该平衡 pilot 代表真实市场分布；Cisco 结果就是本项目创新。

## 下一步

进入错误分析，优先处理四组：

1. 10 个 normal 误报；
2. 6 个 malicious 漏判；
3. 15 个 suspicious→malicious 过度判定；
4. T09 风险召回最低的问题。

从这些错误中选择 2–3 个具有清晰证据链的增量方向，再在同一 90 条上进行配对对比。
