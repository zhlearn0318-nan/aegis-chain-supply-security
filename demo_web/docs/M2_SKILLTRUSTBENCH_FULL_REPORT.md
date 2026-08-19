# SkillTrustBench 全量数据集 Cisco 静态扫描报告

> 运行 ID：`2026-08-14-skilltrustbench-full-cisco-parallel-v1`  
> 最终状态：`completed_with_abstentions`  
> 数据规模：5,520 条完整 v1.0 真值样本  
> 结论等级：`accepted_with_caveats`

## 1. 一页结论

本轮使用与官方 10% 子集实验相同的 Cisco Skill Scanner、统一准入策略、标签映射和失败闭锁规则，对 SkillTrustBench v1.0 全部 5,520 条样本进行本地离线静态评测。5,520/5,520 条均产生终态，其中 5372 条完成 Cisco 扫描，148 条按 `UNKNOWN/abstain` 计入严格指标。

核心结果：覆盖率 97.32%，strict macro F1 为 0.5090，恶意严格召回率 71.11%；统一策略层 non-normal 二分类 precision 为 86.43%、recall 为 77.38%、loose F1 为 81.65%、正常样本 FPR 为 28.67%。这些结果能够描述当前冻结配置在该公开基准上的表现，但不能证明系统对现实世界未知攻击具有同等效果，也不能替代动态验证。

## 2. 数据与安全边界

数据来自 [SkillTrustBench](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench)，本轮固定到审计刷新提交并使用完整 `ground_truth.json` 作为唯一标签来源。

| 项目 | 固定值 |
|---|---|
| 数据集 | SkillTrustBench v1.0 audited refresh |
| 数据提交 | `762d5388b3a047b26df9679582af868a0e5b2c8f` |
| ground truth SHA-256 | `46009af2edd1119901d4e0a1e139f5bf555c769b28b1a2fe2235051f6a902660` |
| 完整 ZIP SHA-256 | `e1d8950ef01c3b24fa80e32101844abc8c5ab3a0a38525427e8b16f00a414ae4` |
| 样本 ID SHA-256 | `99ed464424ef589d76d28f5762fd88dc0b62bd96dc88dfcd9a5b867add9ab4a1` |
| 许可证 | CC BY-NC-SA 4.0 |
| 标签分布 | normal 1,643 / suspicious 1,014 / malicious 2,863 |
| 本机可扫描 | 5451 |
| 本机不可扫描 | 69 |

- 不执行、不导入、不安装样本或样本依赖。
- 不开启 LLM、AI Defense、VirusTotal、云上传或行为分析。
- 仅允许 `static_analyzer`、`bytecode`、`pipeline`；本轮实际观察到：`bytecode`、`pipeline`、`static_analyzer`。
- 每条可扫描样本在 Cisco 扫描前后计算 tree SHA-256；发生变化即停止整批。本轮变化数为 0。
- 端点防护或 Windows 路径规则阻止的样本不绕过、不改名，直接记为 UNKNOWN。

## 3. 运行配置与效率

| 项目 | 结果 |
|---|---:|
| 并发扫描进程 | 4 |
| 活跃墙钟时间 | 145.43 分钟 |
| 吞吐 | 37.96 条/分钟 |
| 单样本中位耗时 | 6,180.0 ms |
| 单样本 P95 | 6,487 ms |
| 单样本最大耗时 | 47,839 ms |
| 单条超时 | 150 秒 |

并发后的单样本耗时包含 CPU 与磁盘资源竞争，不能直接与顺序扫描的约 4 秒中位数解释为扫描器变慢；批量效率应主要观察墙钟时间与吞吐。按上轮 4.028 秒中位数粗略估算，5,520 条顺序运行约需 370 分钟；本轮实际为 145.43 分钟，约缩短到估算顺序时间的 39%。该比例是工程估算，不是严格的同批次单线程对照。首次运行命令为：

```powershell
'F:\揭榜挂帅\supply_chain_reproduction\.runtime_mcp313\Scripts\python.exe' 'F:\揭榜挂帅\supply_chain_reproduction\demo_web\tools\evaluation\run_skilltrustbench.py' --mode full --output-dir 'F:\揭榜挂帅\supply_chain_reproduction\demo_web\artifacts\analysis\2026-08-14-skilltrustbench-full-cisco-parallel-v1' --timeout-seconds 150 --workers 4
```

## 4. 总体扫描结果

### 4.1 三分类严格指标

| 指标 | 结果 |
|---|---:|
| 处理样本 | 5520 / 5520 |
| Cisco 完成扫描 | 5372 |
| abstain | 148 |
| coverage | 97.32% |
| failure rate | 2.68% |
| strict macro F1 | 0.5090 |
| covered macro F1 | 0.5157 |
| 三分类准确率 | 60.07% |
| malicious recall | 71.11% |
| malicious FNR | 28.89% |
| non-normal recall | 77.38% |
| normal FPR | 28.67% |

### 4.2 统一策略层 non-normal 二分类

| 指标 | 结果 |
|---|---:|
| TP | 3000 |
| FP | 471 |
| FN | 877 |
| TN | 1144 |
| precision | 86.43% |
| recall | 77.38% |
| loose F1 | 81.65% |
| FPR | 28.67% |

### 4.3 三分类混淆矩阵

行是真值，列是系统预测。

| ground truth | normal | suspicious | malicious | abstain | 合计 |
|---|---:|---:|---:|---:|---:|
| normal | 1144 | 270 | 201 | 28 | 1643 |
| suspicious | 323 | 136 | 539 | 16 | 1014 |
| malicious | 434 | 289 | 2036 | 104 | 2863 |

## 5. T01–T09 风险类型召回

“detected”指策略结果为 REVIEW 或 BLOCK；风险标签允许多选。

| 风险类型 | support | detected | recall |
|---|---:|---:|---:|
| T01 | 1425 | 1137 | 79.79% |
| T02 | 164 | 136 | 82.93% |
| T03 | 812 | 601 | 74.01% |
| T04 | 2860 | 2282 | 79.79% |
| T05 | 1077 | 757 | 70.29% |
| T06 | 96 | 42 | 43.75% |
| T07 | 124 | 102 | 82.26% |
| T08 | 240 | 234 | 97.50% |
| T09 | 1120 | 752 | 67.14% |

## 6. 失败与不可扫描案例

| 类型 | 数量 |
|---|---:|
| `EndpointProtectionBlocked` | 61 |
| `PlatformPathIncompatible` | 8 |
| `RuntimeError` | 79 |

失败与不可扫描结果全部按 UNKNOWN 处理，没有被当作 normal 放行。端点防护和平台不兼容案例的原始身份仍由完整 ZIP 与归档内 tree hash 固定；Cisco 运行时错误只保留脱敏错误类型，不传播不可信错误正文。

按真值进一步拆分为：`EndpointProtectionBlocked`-malicious 61 条、`PlatformPathIncompatible`-malicious 5 条、`PlatformPathIncompatible`-normal 2 条、`PlatformPathIncompatible`-suspicious 1 条、`RuntimeError`-malicious 38 条、`RuntimeError`-normal 26 条、`RuntimeError`-suspicious 15 条。其中 61 条端点防护阻断全部是 malicious，这说明安全软件本身提供了额外保护，但本系统仍把它们计为 UNKNOWN，而没有借用 Defender 结果冒充 Cisco 检出。

## 7. 误报与漏报

- non-normal 风险筛查漏报：877 条；主要 base category 为 `wild_real_world` 204 条（23.26%）、`api_integration` 121 条（13.80%）、`content_gen` 77 条（8.78%）、`devtool` 74 条（8.44%）、`data_tool` 62 条（7.07%）、`agent_ops` 62 条（7.07%）、`crypto_wallet` 61 条（6.96%）、`productivity` 56 条（6.39%）。
- 漏报主要来源为 `injected` 538 条（61.35%）、`wild_diffused` 125 条（14.25%）、`injected_d11` 124 条（14.14%）、`wild_expanded` 46 条（5.25%）、`wild` 33 条（3.76%）、`safe_pool` 7 条（0.80%）、`external_overtly_malicious_skills` 2 条（0.23%）、`injected_p0_normal_base` 2 条（0.23%）。
- base category 召回最低的五类为 `wild_real_world` 38/242（15.70%）、`devtool` 181/255（70.98%）、`productivity` 188/244（77.05%）、`content_gen` 283/360（78.61%）、`system_admin` 206/254（81.10%）；其中 `wild_real_world` 明显低于其他类别，是当前最重要的泛化短板。
- malicious 严格漏报：827 条，其中预测为 REVIEW 的案例仍会进入人工复核，但在三分类严格口径中记为错误。
- normal 误报：471 条；常见触发规则为 `TOOL_ABUSE_UNDECLARED_NETWORK`（164 个正常误报案例）、`DATA_EXFIL_NETWORK_REQUESTS`（95 个正常误报案例）、`DATA_EXFIL_JS_FS_ACCESS`（77 个正常误报案例）、`FILE_MAGIC_MISMATCH`（42 个正常误报案例）、`SECRET_GITHUB_TOKEN`（31 个正常误报案例）、`SECRET_STRIPE_KEY`（31 个正常误报案例）、`COMMAND_INJECTION_JS_CHILD_PROCESS`（30 个正常误报案例）、`SOCIAL_ENG_MISLEADING_DESC`（23 个正常误报案例）。

这些错误切片用于确定下一轮规则与动态验证优先级，不应在同一全量数据上反复调参后继续把结果当作无偏测试成绩。

## 8. 与官方固定 10% 子集实验对照

10% 清单是全量数据的一部分，不是独立测试集。下表用于检查结论稳定性与抽样偏差，不能作为两个独立总体的显著性比较。

| 指标 | 官方 10%（556） | 全量（5,520） | 变化 |
|---|---:|---:|---:|
| coverage | 98.20% | 97.32% | -0.88 pp |
| failure rate | 1.80% | 2.68% | +0.88 pp |
| strict macro F1 | 0.4977 | 0.5090 | +0.0113 |
| malicious recall | 72.28% | 71.11% | -1.17 pp |
| non-normal recall | 76.67% | 77.38% | +0.71 pp |
| normal FPR | 24.70% | 28.67% | +3.97 pp |
| 策略层 precision | 87.94% | 86.43% | -1.51 pp |
| 策略层 loose F1 | 81.92% | 81.65% | -0.26 pp |

10% 子集与全量实验保持扫描器、策略、标签映射及失败闭锁口径一致；执行方式由顺序扫描改为 4 路并发，因此准确率类指标可以直接核对，单样本延迟则需结合资源竞争解释。

重叠复现检查覆盖 556 条固定 10% 案例，其中 546 条在两轮中均由 Cisco 完成扫描。忽略因本地目录不同而必然变化的绝对路径后，最终决策、预测标签、分析器、告警汇总、策略规则和告警规则集合共有 0 条不一致；扫描终态变化 0 条。该检查用于发现并发、数据复制或运行环境造成的结论漂移。

## 9. 指标含义与证据边界

- `strict macro F1`：normal、suspicious、malicious 三类 F1 的等权平均；UNKNOWN 按错误计。
- `malicious recall`：恶意样本中最终判为 BLOCK/malicious 的比例；判为 REVIEW 仍是严格三分类错误。
- `non-normal recall`：malicious 或 suspicious 中被送入 REVIEW/BLOCK 的比例，更贴近安全准入筛查。
- `normal FPR`：正常样本被送入 REVIEW/BLOCK 的比例，反映人工复核与业务阻断压力。
- 公开基准中的模板注入和变异样本与真实生产分布不同；当前结果不能外推为生产环境检出率。
- 全量公开数据已被用于本次最终评测。后续如果依据这些错误案例开发规则，应另建冻结测试集或引入第二数据集评估泛化。

## 10. 下一步开发建议

1. 从全量风险漏报中按 `wild_real_world`、`crypto_wallet` 和最低召回 T 类建立小规模开发集，另留不参与调参的回归集。
2. 对正常误报最高频规则增加“声明能力—实际行为—目标对象”的上下文条件，不全局降低严重度。
3. 动态验证先使用无害自建 fixture，采集进程、网络、文件写入和敏感环境变量访问；真实恶意样本只在专门隔离沙箱中处理。
4. 大模型只复核静态 UNKNOWN/冲突或高价值样本，并单独比较召回提升、误报、耗时与成本，不能替代确定性规则和动态证据。

## 11. 证据文件

- 运行清单：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/run_manifest.json`
- 逐 case 结果：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/per_case_results.jsonl`
- 指标：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/metrics.json`
- 混淆矩阵：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/confusion_matrix.json`
- 正常误报：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/false_positive_cases.jsonl`
- 恶意严格漏报：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/false_negative_cases.jsonl`
- 全部分类错误：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/classification_errors.jsonl`
- 运行日志：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/run.log`
- 独立验收：`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/verification.json`
- 全量安全导入清单：`../datasets/skilltrustbench_v1_0/full/intake_manifest.json`
