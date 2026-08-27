# 第三方 Skill 试点基线 v1

本基线在首次扫描前冻结 40 个样本：24 个来自 MaliciousAgentSkillsBench 的真实生态 Skill，16 个来自 SkillTrustBench 的强标签样本。样本 ID、来源提交、许可证对象、文件哈希、选择种子和指标合同均已固定。

## 用途边界

- 16 个 SkillTrustBench 样本用于三分类工程指标，比例为正常 8、可疑 4、恶意 4，并覆盖 T01–T09。
- 24 个 MaliciousAgentSkillsBench `safe` 样本只用于真实生态兼容性、规则触发分布和误报线索观察。论文明确说明该类只是通过静态漏斗，不能当作逐样本行为确认的正常真值。
- 本集合是小规模分层诊断集，不用于推断真实生态风险率。
- 扫描器不得读取清单中的 ground truth；标签只在扫描完成后参与评估。

## 动态执行边界

强标签为 suspicious/malicious 的样本永不执行。其余样本还必须同时满足静态决策为 ALLOW/REVIEW、恰好一个保守识别的 Python `scripts/` 入口、无链接和二进制，并在断网容器中受时间/资源限制运行。当前仅 1 个样本是静态扫描前候选，尚未执行。

## 可复现入口

```powershell
..\.runtime_mcp313\Scripts\python.exe tools\datasets\prepare_third_party_skill_pilot.py
```

原始样本位于仓库外的 `datasets/third_party_skill_pilot40_v1`；仓库内保存来源锁、样本 ID、指标合同和校验证据。
