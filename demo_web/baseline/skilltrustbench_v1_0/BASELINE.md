# SkillTrustBench v1.0 pilot 基线

状态：`comparison_ready / accepted_with_caveats`

本基线固定 SkillTrustBench v1.0 audited refresh 的来源、许可、90 条 pilot、标签映射和计分规则。它是后续 Cisco 静态扫描批量实验的对照输入，不包含扫描准确率结果。

## 固定内容

- 数据仓库：`cuhk-zhuque/SkillTrustBench`
- 内容 revision：`762d5388b3a047b26df9679582af868a0e5b2c8f`
- pilot：90 条，`normal / suspicious / malicious` 各 30 条
- 抽样 seed：`aegis-chain-skilltrustbench-pilot-v1`
- case ID 清单 SHA-256：`59dd01a97225b9efef24fa0a7a7a0213fd7e36614b71f5adb7522d16fa518800`
- 主指标：`strict_macro_f1`
- 失败处理：扫描失败或 `UNKNOWN` 记为 abstain；严格指标中按错误计，同时单列 coverage 与 failure rate

## 文件

- `json/metric_contract.json`：冻结的标签映射、指标、方向和计算边界。
- `provenance.json`：数据来源、版本、导入命令和许可。
- `verification.json`：本地哈希、样本分布、安全边界和测试结果。
- `pilot_case_ids.txt`：可提交、无样本正文的固定 case ID 清单。
- `local_acceptance.json`：本次本地基线接受结论及限制。

原始数据位于 `supply_chain_reproduction/datasets/skilltrustbench_v1_0/`。工作区根 `.gitignore` 已加入排除规则；当前工作区尚无有效 Git 仓库，因此还不能执行 `git check-ignore` 复核。不得安装、导入或执行其中任何 Skill。

## 下一锚点

实现批量静态评测运行器，先用 3–5 条样本验证 Cisco Skill Scanner 输入适配和超时，再运行固定 90 条 pilot。任何自研规则必须在首轮基线结果保存后才能修改。
