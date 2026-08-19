# SkillTrustBench 官方 10% 子集 Cisco 静态扫描报告

> 运行日期：2026-08-14  
> 运行 ID：`2026-08-14-skilltrustbench-official10pct-cisco-v1`  
> 最终状态：`completed_with_abstentions`  
> 结论等级：`accepted_with_caveats`

## 1. 一页结论

本轮已将样本量从 90 条扩大到 SkillTrustBench 官方固定 10% 子集的 556 条，并使用相同的 Cisco Skill Scanner、统一准入策略和三分类映射完成本地静态扫描。556/556 条均产生终态，其中 546 条由 Cisco 完成扫描，7 条发生 Cisco 运行时错误，3 条真实恶意样本被 Windows Defender 隔离；后 10 条均按失败闭锁规则记为 `UNKNOWN/abstain`，没有当作安全样本放行。

核心结果：覆盖率 98.20%，strict macro F1 为 0.4977，恶意样本严格召回率 72.28%，统一策略层的 non-normal 二分类召回率 76.67%、FPR 24.70%、loose F1 81.92%。这说明当前系统已经具备可运行、可追溯、可批量复现的静态准入门能力，但不能独立作为最终安全裁决：仍有 91 条风险样本未被送入 REVIEW/BLOCK，尤其是 wild real-world 和 T06/T09/T05 风险需要优先补强。

## 2. 本轮具体完成了什么

1. 锁定官方结果仓库提交与固定子集文件，复算 556 条 ID 哈希并与官方榜单一致。
2. 将 556 条样本与完整 ground truth 逐条交叉校验，确认标签与风险类型无不一致。
3. 对 ZIP 路径穿越、符号链接、成员数量、单文件大小和总解压大小做安全审计，只解压指定 case，不执行、不导入、不安装任何样本代码。
4. 为 556 条样本生成逐 case tree SHA-256，并将可读样本文件设为只读。
5. 为批量运行器增加 `official10` 模式、统一策略层二分类指标和断点续扫。
6. 顺序执行 Cisco 本地静态扫描；在第 529 条后因 Defender 隔离触发停止，修正安全终态逻辑后复核 529 条前缀并从断点继续，没有重扫已完成样本。
7. 独立复算指标、混淆矩阵与错误切片，校验 8 个运行输出的 SHA-256；最终后端测试 `73 passed`。

## 3. 数据来源与可复现身份

官方数据集为 [SkillTrustBench](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench)，固定评测清单及公开榜单来自 [SkillTrustBench-results](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench-results)。官方协议将当前公开评测限定为固定 10% 子集，并把 malicious 与 suspicious 合并为 non-normal 筛查目标。

| 项目 | 固定值 |
|---|---|
| SkillTrustBench 数据提交 | `762d5388b3a047b26df9679582af868a0e5b2c8f` |
| 结果仓库提交 | `326ec286d082199cb270b25b8b4fc93c8762281e` |
| 子集文件 SHA-256 | `dff7621ffcc7a42f1a8ff64c8e47d2fafc1cd332431fd533be88bb684aaa6843` |
| 排序 ID + LF + 末尾换行 SHA-256 | `903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2` |
| 样本数 | 556 |
| 标签分布 | normal 166 / suspicious 105 / malicious 285 |
| 许可证 | CC BY-NC-SA 4.0 |

固定子集包含 390 条 non-normal 与 166 条 normal。官方清单、完整 ground truth 和压缩包内 case 目录三方核对结果均为 556/556 一致，无重复 ID、无缺失目录。

## 4. 扫描环境与冻结契约

| 项目 | 本轮设置 |
|---|---|
| 操作系统 | Windows 11，本地 CPU，顺序扫描 |
| Python | 3.13.14 |
| Cisco Skill Scanner | `2.0.13.dev3+g4dee90371` |
| 扫描器可执行文件 SHA-256 | `b31b66fce1b8466ba5c49e1084ee972b746e00d4ebdcaeab78ad6b38a0dce366` |
| 策略 | `aegis-chain-local-default` 1.0.0 |
| 策略 SHA-256 | `010ca27b327e5098b11d7819563b40a607cac7698ac01019740557b8eaececf5` |
| 单条超时 | 150 秒 |
| 允许分析器 | `static_analyzer`、`bytecode`、`pipeline` |
| LLM/云上传/行为执行 | 全部关闭 |
| 样本依赖安装 | 未执行 |
| 原始样本证据保存 | 未保存，仅保留脱敏 Finding 索引 |

首次命令：

```powershell
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\run_skilltrustbench.py --mode official10 --output-dir artifacts\analysis\2026-08-14-skilltrustbench-official10pct-cisco-v1 --timeout-seconds 150
```

断点恢复命令：

```powershell
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\run_skilltrustbench.py --mode official10 --output-dir artifacts\analysis\2026-08-14-skilltrustbench-official10pct-cisco-v1 --timeout-seconds 150 --resume
```

运行器对子进程设置 `LITELLM_LOCAL_MODEL_COST_MAP=True`、`HF_HUB_OFFLINE=1`、`TRANSFORMERS_OFFLINE=1`，并移除 OpenAI、Anthropic、VirusTotal 和 Cisco AI Defense 等凭据。运行总墙钟时间约 39 分钟，包含中断定位与断点恢复。

## 5. 指标口径

### 5.1 三分类严格指标

- ground truth：normal / suspicious / malicious。
- 策略输出：ALLOW→normal、REVIEW→suspicious、BLOCK→malicious、UNKNOWN→abstain。
- abstain 在 strict macro F1、召回率和准确率中按错误计。
- 恶意严格召回只把 BLOCK 视为正确；恶意→REVIEW 在三分类中仍是错误，但在安全筛查二分类中算已发现风险。

### 5.2 补充 non-normal 二分类

- ground truth malicious 或 suspicious：risk-positive。
- 本系统策略输出 BLOCK 或 REVIEW：预测 risk-positive。
- ALLOW 或 UNKNOWN：未发现风险，其中 UNKNOWN 仍单独报告为 abstain。

该补充指标是 Aegis Chain 统一策略层的结果，不等同于官方 Cisco 榜单。官方结果文件说明 Cisco 行直接使用扫描器的 `actual_safe` 字段，并使用 DeepSeek v4 Flash 支持的工具比较设置；本轮是本地离线、无 LLM 的统一策略映射。因此只能作为外部参照，不能声称复现官方 Cisco 分数。

## 6. 扫描结果

### 6.1 核心三分类指标

| 指标 | 结果 |
|---|---:|
| 处理样本 | 556 / 556 |
| Cisco 完成扫描 | 546 |
| abstain | 10 |
| coverage | 98.20% |
| failure rate | 1.80% |
| strict macro F1 | 0.4977 |
| covered macro F1 | 0.5023 |
| 三分类准确率（补充） | 60.61% |
| malicious recall | 72.28% |
| malicious FNR | 27.72% |
| non-normal recall | 76.67% |
| normal FPR | 24.70% |
| 中位耗时 | 4,028 ms |
| P95 耗时 | 4,309 ms |
| 最大耗时 | 5,437 ms |

### 6.2 统一策略层二分类结果

| 指标 | 结果 |
|---|---:|
| TP | 299 |
| FP | 41 |
| FN | 91 |
| TN | 122 |
| abstain | 10 |
| precision | 87.94% |
| recall | 76.67% |
| loose F1 | 81.92% |
| FPR | 24.70% |

### 6.3 三分类混淆矩阵

行是真值，列是系统预测。

| ground truth | normal | suspicious | malicious | abstain | 合计 |
|---|---:|---:|---:|---:|---:|
| normal | 122 | 22 | 19 | 3 | 166 |
| suspicious | 38 | 9 | 57 | 1 | 105 |
| malicious | 46 | 27 | 206 | 6 | 285 |

## 7. T01–T09 风险类型召回

风险类型允许一条样本包含多个标签；“detected”指策略结果为 REVIEW 或 BLOCK。

| 风险类型 | support | detected | recall |
|---|---:|---:|---:|
| T01 | 147 | 121 | 82.31% |
| T02 | 16 | 12 | 75.00% |
| T03 | 78 | 60 | 76.92% |
| T04 | 289 | 229 | 79.24% |
| T05 | 111 | 74 | 66.67% |
| T06 | 10 | 4 | 40.00% |
| T07 | 12 | 11 | 91.67% |
| T08 | 25 | 24 | 96.00% |
| T09 | 112 | 70 | 62.50% |

最需要补强的是 T06、T09、T05。T06 和 T07 的 support 较小，百分比不稳定，但 T06 的 4/10 仍足以列为高优先级人工复核对象。

## 8. 失败与安全事件

### 8.1 Cisco 运行时错误：7 条

| case | 真值 | 处理 |
|---|---|---|
| `case_00878` | malicious | UNKNOWN/abstain |
| `case_02419` | suspicious | UNKNOWN/abstain |
| `case_03619` | normal | UNKNOWN/abstain |
| `case_03886` | malicious | UNKNOWN/abstain |
| `case_04444` | normal | UNKNOWN/abstain |
| `case_05510` | normal | UNKNOWN/abstain |
| `case_05548` | malicious | UNKNOWN/abstain |

原始扫描器错误文本未保留，避免传播样本内容。运行时错误未重试，也未启用 lenient frontmatter 或修改样本；后续应在隔离环境中只记录错误阶段和错误码，定位兼容性问题。

### 8.2 Windows Defender 隔离：3 条

`case_05527`、`case_05559`、`case_05568` 均为 malicious。导入时已通过固定压缩包字节计算 tree hash，随后 Defender 阻止读取或隔离了 `SKILL.md`。系统没有关闭 Defender、没有增加排除目录、没有重新释放样本，也没有调用 Cisco 扫描器，而是按 UNKNOWN/abstain 记入结果。

### 8.3 断点恢复

首次运行在处理完 529 条后因隔离文件缺失停止。恢复前校验了：运行 ID、模式、556 条顺序、数据提交、清单 SHA-256、扫描器 SHA-256、策略 SHA-256、指标契约 SHA-256，以及前 529 条逐样本 before/after hash。全部一致后才从第 530 条继续。

## 9. 误报与漏报分析

### 9.1 风险筛查漏报

- 91 条 non-normal 没有进入 REVIEW/BLOCK：39 条 suspicious、52 条 malicious。
- 79 条 malicious 未被严格预测为 malicious，其中 27 条被 REVIEW，仍进入了人工复核；46 条被 ALLOW，6 条为 abstain。
- 漏报最多的场景是 `wild_real_world`（21 条）、`api_integration`（15 条）和 `crypto_wallet`（11 条）。
- `wild_real_world` 风险筛查召回仅 6/27（22.22%）；`crypto_wallet` 为 16/27（59.26%）。这两个切片应成为自研规则与动态验证的第一优先级。

### 9.2 正常样本误报

- 166 条 normal 中有 41 条被判为 non-normal：22 条 REVIEW、19 条 BLOCK。
- 误报触发中较常见的规则包括 `DATA_EXFIL_JS_FS_ACCESS`、`TOOL_ABUSE_UNDECLARED_NETWORK`、`DATA_EXFIL_NETWORK_REQUESTS` 和 `FILE_MAGIC_MISMATCH`。
- `devtool` 正常样本 FPR 为 5/11（45.45%），`scraper` 为 3/7（42.86%），`crypto_wallet` 为 6/18（33.33%）。前两个切片 support 较小，适合逐案审查，不能直接推广为整体结论。

这表明网络请求、文件访问和编码/格式异常规则缺少上下文：同一种 API 在合法工具中可能是业务必需，在恶意样本中也可能用于外传。下一步不应简单下调所有严重度，而应增加“声明能力—实际行为—目标域/数据类型”的上下文关联。

## 10. 与 90 条基线的对照

90 条 pilot 三类各 30 条；556 条官方子集为 166/105/285，且包含 wild real-world 样本。因此下表只能用于判断工程稳定性和风险方向，不能把差值解释成同分布下的性能变化。

| 指标 | pilot90 | 官方 556 | 变化 |
|---|---:|---:|---:|
| coverage | 98.89% | 98.20% | -0.69 pp |
| failure rate | 1.11% | 1.80% | +0.69 pp |
| strict macro F1 | 0.5114 | 0.4977 | -0.0137 |
| malicious recall | 80.00% | 72.28% | -7.72 pp |
| non-normal recall | 78.33% | 76.67% | -1.67 pp |
| normal FPR | 33.33% | 24.70% | -8.63 pp |
| 策略层 loose precision | 82.46% | 87.94% | +5.49 pp |
| 策略层 loose F1 | 80.34% | 81.92% | +1.58 pp |
| 中位耗时 | 3,935 ms | 4,028 ms | +93 ms |
| P95 耗时 | 4,226 ms | 4,309 ms | +83 ms |

稳定结论是：覆盖率仍约 98%，单条耗时仍约 4 秒，strict macro F1 仍约 0.50，策略层 loose F1 仍约 0.80。需要修正的认识是：90 条样本对恶意严格召回偏乐观；扩大到官方子集后下降到 72.28%，wild real-world 暴露出明显短板。

## 11. 与官方 Cisco 榜单的关系

官方结果仓库中的 Cisco 行为 precision 90.07%、recall 95.38%、loose F1 92.65%、FPR 24.70%。本轮对应的策略层结果为 87.94%、76.67%、81.92%、24.70%。即便 FPR 四舍五入后相同，也不能称为复现，原因包括：

- 官方 Cisco 行直接用 `actual_safe` 二分类，本轮经过 Aegis Chain 严重度与准入策略映射。
- 官方工具比较行标注 DeepSeek v4 Flash，本轮完全关闭 LLM 与云分析。
- 扫描器版本、运行环境和错误处理方式未证明相同。
- 本轮 10 个 abstain 在严格召回中按错误计。

因此，正式汇报可以说“在相同官方 556 条清单上完成了本地离线策略层评测”，不能说“复现了官方 Cisco 榜单成绩”。

## 12. 验收结果

- 556/556 结果顺序与固定清单一致。
- 8 个声明输出的文件大小和 SHA-256 全部一致。
- 指标、混淆矩阵、FP/FN/全部错误切片可从逐 case 结果完全复算。
- 553 条 scanner-eligible 样本 before/after tree hash 无差异。
- 3 条 Defender 样本仅使用固定归档身份，不绕过端点防护。
- 分析器集合严格为 `static_analyzer`、`bytecode`、`pipeline`。
- 脱敏 Finding 只保留 ID、规则、类别、严重度、分析器和位置；无原始 evidence、description、remediation。
- 后端测试：`73 passed`。

## 13. 下一步开发优先级

### P0：先处理召回短板

1. 建立 91 条 risk-screening miss 清单，优先人工审查 21 条 wild real-world 与 11 条 crypto_wallet 漏报。
2. 针对 T06、T09、T05 各选择 5–10 个代表样本，提炼“静态可观测特征—缺失规则—预期严重度”。
3. 新规则只在同一官方 556 条上做冻结前开发、冻结后一次复测，避免边看测试集边调参造成过拟合。

### P1：降低上下文误报

1. 为网络、文件系统、密钥字符串和编码异常增加上下文条件，不全局降低严重度。
2. 优先复核 devtool、scraper、crypto_wallet 正常样本误报。
3. 将“声明了网络能力”和“未声明却调用网络”分开处理，并记录目标域与数据来源。

### P1：补动态验证最小闭环

只对静态结果为 REVIEW/BLOCK 或高价值 ALLOW 的少量样本进入隔离动态阶段，先实现：进程创建、网络连接、文件写入、敏感环境变量访问四类行为事件。动态阶段不得直接运行本数据集中的真实恶意样本；应先使用自建无害模拟 fixture 验证监控链路，再决定是否使用专门沙箱。

### P2：第二工具对照

可在完全相同的 556 条 ID 和二分类契约上接入另一开源 Skill 扫描器，测量互补召回；MCP Scanner 应用于 MCP server/config 样本，不应强行用于 SkillTrustBench。所有外部工具必须保留原始输出适配层与统一策略层之间的边界，避免把厂商分数直接当作系统最终结论。

## 14. 证据文件

- 运行清单：`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/run_manifest.json`
- 逐 case 结果：`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/per_case_results.jsonl`
- 指标：`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/metrics.json`
- 混淆矩阵：`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/confusion_matrix.json`
- 误报：`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/false_positive_cases.jsonl`
- 恶意严格漏报：`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/false_negative_cases.jsonl`
- 全部分类错误：`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/classification_errors.jsonl`
- 运行日志：`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/run.log`
- 安全导入清单：`../datasets/skilltrustbench_v1_0/official_10pct/intake_manifest.json`
