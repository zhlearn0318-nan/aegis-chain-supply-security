# SkillTrustBench v1.0 全量 Cisco 静态基线

状态：`comparison_ready / accepted_with_caveats`

本目录冻结 `2026-08-14-skilltrustbench-full-cisco-parallel-v1` 的 5,520 条全量结果。冻结后不得修改原始运行目录；后续规则和语义增强只在开发集上设计，并用封存回归集检查工程退化。

## 核心结果

- coverage：97.32%
- strict macro F1：0.5090
- malicious recall：71.11%
- non-normal recall：77.38%
- normal FPR：28.67%
- abstention：148 / 5,520

## 边界

这是一份经过独立复算和哈希核验的工程基线，但并非预注册盲测。完整数据已经参与误差分析，因此后续不能把同一 5,520 条上的调优结果称为无偏最终成绩。

`freeze_manifest.json` 固定证据文件身份，`FREEZE_SHA256.txt` 固定冻结清单自身身份，`json/metric_contract.json` 固定比较口径。
