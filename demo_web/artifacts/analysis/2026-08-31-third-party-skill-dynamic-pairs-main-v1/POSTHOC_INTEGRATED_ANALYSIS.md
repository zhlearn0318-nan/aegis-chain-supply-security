# 静态 + 动态综合准入补充分析（主实验后分析）

> 本文件不改变主实验样本、规则、阈值或结论，只基于已冻结输出计算综合决策。

## 综合结果

- 6 个真实原始 Skill：动态层 {'ALLOW': 6}，综合准入 {'ALLOW': 1, 'BLOCK': 1, 'REVIEW': 4}；
- 原始 Skill 动态干净率：100.0%；
- 原始 Skill 最终综合 ALLOW 率：16.7%；
- 30 个风险孪生：静态非放行 26/30（86.7%），动态非放行 30/30（100.0%），综合非放行 30/30；
- 动态审计补齐静态 ALLOW 漏洞：4 个；
- 动态证据使决策更严格：18 个，其中包含上述 4 个新增非放行和 14 个 REVIEW→BLOCK。

## 评委视角解释

动态审计的价值已经被真实容器证据证明：它不误伤本轮 6 个真实脚本，能够补齐静态规则对运行时条件触发行为的遗漏，并给 REVIEW 样本提供可复核的阻断证据。

但不能把“动态层 6/6 ALLOW”说成“最终系统 6/6 放行”。当前融合策略是单调的：动态干净不能消除静态 HIGH/MEDIUM 风险。因此最终只有 Anthropic `algorithmic-art` 为 ALLOW，4 个 OpenAI Skill 为 REVIEW，`security-ownership-map` 因包内另一个可执行入口存在动态命令流而保持 BLOCK。

这意味着下一阶段若要提高真实日常可用性，重点不是放松动态检测，而是完善静态证据范围：区分“本次拟执行入口”与“包内其他未调用能力”，对 Notebook 等非代码资产建立专用解析器，并把语义条件触发从通用 MEDIUM 候选细化为有数据流证据的规则。未经这些证据，不应让动态 ALLOW 自动覆盖静态 BLOCK。

## 逐个原始 Skill 综合决策

| Skill | 静态 | 动态 | 综合 |
|---|---|---|---|
| openai-jupyter-notebook--original | REVIEW | ALLOW | REVIEW |
| openai-plugin-creator--original | REVIEW | ALLOW | REVIEW |
| openai-security-ownership-map--original | BLOCK | ALLOW | BLOCK |
| openai-chatgpt-apps--original | REVIEW | ALLOW | REVIEW |
| openai-openai-docs--original | REVIEW | ALLOW | REVIEW |
| anthropic-algorithmic-art--original | ALLOW | ALLOW | ALLOW |
