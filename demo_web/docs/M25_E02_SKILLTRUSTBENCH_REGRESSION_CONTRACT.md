# M25 E02 SkillTrustBench 600 条恶意回归合同

> 状态：回归运行前冻结  
> 数据：既有 SkillTrustBench 工程回归集 600 条，normal/suspicious/malicious 各 200 条  
> 目标：比较当前 F0 与 E02 F3 候选，不重新调用 Cisco，不执行任何 Skill。

本轮复用已冻结的 Cisco 父结果，重新运行当前 Aegis 静态分析器，再对同一发现集合分别执行 F0 与 F3。比较指标为 malicious 的非放行召回（REVIEW 或 BLOCK）；F3 相对 F0 下降不得超过 2 个百分点。

完整 HIGH 数据流规则不得降级；扫描失败保持 UNKNOWN。该 600 条集合已经用于既有工程回归，不作为新的独立论文测试集，也不用于继续逐样本调规则。
