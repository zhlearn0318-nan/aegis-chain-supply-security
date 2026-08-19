# SkillTrustBench v1.0 数据集入口审计

> 审计日期：2026-08-10  
> 用途：Aegis Chain 供应链静态检测评测  
> 当前结论：可用于非商业科研/竞赛评测，但必须静态处理、保留署名与版本证据  
> 阶段：固定版本已导入并验证，90 条 pilot 与评测契约已冻结，准备批量静态扫描

## 1. 一页结论

SkillTrustBench 适合作为本项目的首个外部 Skill 安全评测集，理由是：

- 由腾讯朱雀实验室与香港中文大学（深圳）联合发布；
- 面向 Skill 安全扫描器，而不是一般 Agent 任务能力；
- 提供 5,520 个 `normal / suspicious / malicious` 三类样本；
- 覆盖 T01–T09 九类指令、代码执行、权限、持久化、工具链、依赖和不安全编码风险；
- 官方数据卡直接提供 Cisco Skill Scanner 的评测流程；
- 发布文件提供 SHA-256，可固定版本并复核下载完整性。

但它不是“无条件权威真值”：部分样本是模板注入或变异生成，标签也在发布后做过一次重要修订；截至本次审计，没有找到专门介绍 SkillTrustBench 构造与标注方法的同行评审论文。因此汇报时应称为“腾讯朱雀实验室与香港中文大学（深圳）联合发布的公开基准”，不应称为“已通过同行评审的国际标准数据集”。

## 2. 一手来源

| 来源 | 地址 | 用途 |
|---|---|---|
| 项目官网 | https://matrix.tencent.com/skilltrustbench/ | 发布方、攻击分类与排行榜 |
| 腾讯朱雀发布文章 | https://matrix.tencent.com/zh/2026/06/17/first-skill-trust-bench | 联合发布单位与数据构造概述 |
| Hugging Face 数据仓库 | https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench | 数据文件、字段、许可、安全说明和校验值 |
| v1.0 审计刷新提交 | https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench/commit/762d5388b3a047b26df9679582af868a0e5b2c8f | 310 条标签修订与完整数据重建 |
| 官方结果仓库 | https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench-results | 固定 10% 子集与公开排行榜口径 |

补充论文 `Securing the AI Agent: A Unified Framework for Multi-Layer Agent Red Teaming`（arXiv:2606.31227）主要支持腾讯 A.I.G 的分层安全框架，不等同于 SkillTrustBench 数据集论文，不能替代数据卡中的构造与许可说明。

## 3. 版本与完整性契约

本项目固定：

```text
dataset: cuhk-zhuque/SkillTrustBench
version: v1.0 audited refresh
content revision: 762d5388b3a047b26df9679582af868a0e5b2c8f
download date: 2026-08-10
```

审计提交的仓库对象标识（通过 Hugging Face 官方 API 核验）：

| 文件 | 字节数 | 仓库对象标识 |
|---|---|
| `data/test_cases.jsonl` | 1,304,853 | Git blob SHA-1 `0e6436b80885d619f1c98b772165c4ac4ba4669b` |
| `metadata/case_metadata.jsonl` | 3,115,562 | Git blob SHA-1 `d12dd4cda28971f49586bdcc754d3e3c89f98cf3` |
| `benchmark_full_v1.0/ground_truth.json` | 4,439,440 | Git blob SHA-1 `a50a71dc618e39f3dc08e249dc981c323adac9ed` |
| `benchmark_full_v1.0.zip` | 80,230,995 | LFS SHA-256 `e1d8950ef01c3b24fa80e32101844abc8c5ab3a0a38525427e8b16f00a414ae4` |

当前 README 的校验表仍保留审计刷新前的对象哈希，其中 ZIP 写为 `d65fe2…`；审计提交的 diff 和官方 API 均证明刷新后的 ZIP 为 `e1d895…`。因此导入器不使用过期 README 表，而是以固定 revision 的 Git blob/LFS 对象 ID 和字节数验证下载，再额外记录每个本地文件的 SHA-256。任何一项不一致都立即停止。

2026-08-10 实际导入得到的本地 SHA-256：

| 文件 | 本地 SHA-256 |
|---|---|
| `data/test_cases.jsonl` | `e37f2c1c0539a8e8f8269cb2b015bcc3d3fb4f8d4299273ab6b53be546ed7bec` |
| `metadata/case_metadata.jsonl` | `1ad85b6ab067de3e563bf26e02f3fe177d09ee229aaf227fc37a973c0c191a8b` |
| `benchmark_full_v1.0/ground_truth.json` | `46009af2edd1119901d4e0a1e139f5bf555c769b28b1a2fe2235051f6a902660` |
| `benchmark_full_v1.0.zip` | `e1d8950ef01c3b24fa80e32101844abc8c5ab3a0a38525427e8b16f00a414ae4` |

## 4. 已发现的版本与校验差异

项目网页目前显示：

```text
malicious 2,553 / suspicious 1,324 / normal 1,643
```

Hugging Face 审计刷新后的数据卡显示：

```text
malicious 2,863 / suspicious 1,014 / normal 1,643
```

差异来自 2026-06-15 的 v1.0 审计刷新：310 条 `suspicious` 被升级为 `malicious`。因此：

1. `ground_truth.json` 是本项目唯一真值来源；
2. 不从项目网页截图抄录标签比例；
3. manifest 必须记录 revision 和文件 SHA-256；
4. 评测结果必须注明使用“audited refresh”，不能与初始发布或网页旧比例混合比较。

此外，当前 README 的四个 SHA-256 来自审计刷新前的文件，未随 `762d538…` 重建同步更新。本项目已将该问题记录为上游数据卡一致性缺陷；不把 README 旧哈希当作 audited refresh 的真值。

## 5. 许可结论

当前 Hugging Face 元数据与数据卡标注为 `CC BY-NC-SA 4.0`：

- `BY`：汇报、报告和衍生清单必须署名腾讯朱雀实验室/SkillTrustBench，并给出来源；
- `NC`：只用于本次非商业竞赛、教学和研究；不得据此直接提供商业服务或商业训练数据；
- `SA`：如果公开发布经过修改的数据副本，需要使用兼容的相同许可；
- 原始恶意样本不进入本项目源码提交，只在本地第三方数据目录保存；
- 项目只提交 case ID、标签、哈希、抽样参数和评测结果，减少恶意内容的二次传播。

以上是工程合规判断，不替代法律意见。若未来作品商业化，应重新获得授权或更换允许商业使用的数据集。

建议引用：

```bibtex
@dataset{skilltrustbench_v1_0,
  title   = {SkillTrustBench},
  version = {v1.0},
  year    = {2026},
  note    = {Benchmark dataset for agent skill security evaluation}
}
```

## 6. 数据结构

每条索引记录至少包含：

| 字段 | 含义 |
|---|---|
| `id` | 稳定案例 ID，如 `case_04866`；编号不连续 |
| `judgment` | `normal / suspicious / malicious` |
| `risk_labels` | T01–T09 多标签风险分类 |
| `source` | 样本来源或生成池，不代表业务领域 |
| `base_category` | Skill 功能领域 |
| `primary_pattern` | 主要攻击或漏洞模式 |
| `attack_pattern` | 全部攻击或漏洞模式 |
| `skill_path` | 解压后的案例目录 |

完整案例位于 `benchmark_full_v1.0.zip`，每个 `case_*` 目录包含 `SKILL.md`，并可能包含 `scripts/`、配置、依赖、资源或可执行内容。

## 7. 安全处理边界

官方明确警告部分样本来自真实恶意模式或包含可运行脚本。本项目强制执行：

- 不安装任何 Skill；
- 不导入样本 Python 模块；
- 不执行样本脚本、安装脚本、Shell 命令或依赖；
- 不启用 Cisco LLM、AI Defense、VirusTotal 上传或其他云端分析；
- 只允许 Cisco Static、Bytecode 静态解析和 Pipeline 文本/结构检查；
- 下载后先校验整个 ZIP 的 SHA-256，再检查路径穿越、绝对路径、符号链接、成员数与总解压大小；
- 只解压 pilot 所需 case，原始 ZIP 保持只读缓存；
- 动态沙箱完成前，不对这些样本做任何动态验证。

即使 `judgment=normal`，也按不可信文件处理；标签是评测真值，不是宿主机安全证明。

## 8. 90 条 pilot 抽样契约

pilot 只验证数据适配、扫描稳定性和指标代码，不形成最终准确率结论。

固定参数：

```text
pilot size: 90
normal: 30
suspicious: 30
malicious: 30
seed text: aegis-chain-skilltrustbench-pilot-v1
ordering: SHA-256(seed text + ":" + case id)
```

选择流程：

1. 仅从校验通过的 `ground_truth.json` 读取候选；
2. 在 60 条非正常样本中先用确定性贪心覆盖 T01–T09；
3. 再按哈希顺序填满每类 30 条；
4. 同时保留 `source`、`base_category`、风险标签和原始索引位置；
5. 输出 `pilot_manifest.jsonl`、统计 JSON 和 case ID SHA-256；
6. 抽样完成后不因扫描结果好坏更换样本。

### 8.1 实际导入结果

- 全量真值：5,520 条，其中 `normal 1,643 / suspicious 1,014 / malicious 2,863`；
- ZIP：37,721 个成员，解压前总大小 252,000,754 字节；
- pilot：90 条，三类各 30 条；
- pilot 文件：628 个，共 2,774,819 字节；
- 风险覆盖：T01–T09 全部覆盖，计数分别为 `16/2/9/41/22/2/1/4/29`；
- case ID 清单 SHA-256：`59dd01a97225b9efef24fa0a7a7a0213fd7e36614b71f5adb7522d16fa518800`；
- pilot manifest SHA-256：`0302a9c041499e73a3e0a6c29128f1a6745039bca0b902fdf425c0a2a539806f`；
- 4 个原始文件和 628 个解压文件均设置为只读；工作区根 `.gitignore` 已加入数据目录排除规则，但当前尚无有效 Git 仓库可执行实际检查；
- 第二次运行没有重新下载或重新解压，而是复核全部源对象和 90 个 case tree hash，结果一致。

导入命令：

```powershell
..\.runtime_mcp313\Scripts\python.exe tools\datasets\prepare_skilltrustbench.py
```

## 9. Aegis Chain 标签映射

三分类研究口径：

| Aegis 决策 | SkillTrustBench 预测 |
|---|---|
| `ALLOW` | `normal` |
| `REVIEW` | `suspicious` |
| `BLOCK` | `malicious` |
| `UNKNOWN` / 扫描失败 | `abstain`，不伪装成风险检出 |

必须同时报告：

- `coverage` 与 `failure_rate`；
- strict macro F1：`abstain` 计为错误；
- covered-only macro F1：只用于诊断，不能单独作为主结果；
- malicious recall 与 malicious FNR；
- non-normal recall；
- normal FPR；
- T01–T09 per-label recall；
- 扫描耗时中位数、P95 和最大值。

另设“运营门禁口径”：`REVIEW/BLOCK/UNKNOWN` 均不自动放行。该口径说明失败闭锁效果，不能与检测器 F1 混为一谈。

## 10. 已知限制

- 数据分布是基准构造结果，不代表真实 Skill 市场风险比例；
- 多数风险样本来自注入或变异流程，存在模板泄漏和同族相关性；
- 标签在首次发布后发生过 310 条修订，说明真值仍可能继续演化；
- 三分类与 Cisco 原生输出并非天然一一对应，映射规则必须在跑分前冻结；
- pilot 是工程试运行，不用于排行榜或最终性能宣传；
- 尚未找到独立同行评审的数据集论文。

## 11. Scout 与基线决策

Scout 结论：`GO`。数据来源、许可和安全边界足以进入本地基线导入。

基线结论：`accepted_with_caveats / comparison_ready`。固定 revision、完整性、90 条 pilot、计分契约和重复运行均已验证，但尚未产生任何准确率、召回率或 F1 结果。

下一锚点：实现批量静态评测运行器，先用 3–5 条验证输入适配和超时，再运行固定 90 条 pilot。首轮结果落盘前不增加检测规则、不更换样本、不修改标签映射。

## 12. 首轮 Cisco 静态基线（2026-08-10）

固定 5 条 smoke 通过后，使用同一数据、策略和映射运行全部 90 条。结果为：89 completed、1 `UNKNOWN/abstain`，coverage 98.89%，strict macro F1 0.5114，malicious recall 80%，normal FPR 33.33%。90 条样本 hash 全部不变，只观察到三个允许的本地静态分析器。

唯一失败来自 Cisco `python-frontmatter` 严格解析兼容性，主结果保留 abstain。详细指标、混淆矩阵、错误清单和限制见 `docs/M2_SKILLTRUSTBENCH_BASELINE.md`。数据审计结论不因结果改变；本节只是记录该固定数据入口已经产生首个可比较扫描基线。
