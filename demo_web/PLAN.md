# SkillTrustBench 官方 10% 子集扩大样本复核计划

## 1. 本轮身份

- run id：`2026-08-14-skilltrustbench-official10pct-cisco-v1`
- run type：`analysis_campaign`（稳健性/泛化复核）
- 父实验：`2026-08-10-skilltrustbench-pilot90-v1`
- 扫描器基线：`cisco-static-2026-07-31`
- 数据：SkillTrustBench v1.0 官方固定 10% 子集，共 556 条
- 官方分布：normal 166、suspicious 105、malicious 285

## 2. 研究问题与证据边界

- 核心问题：90 条平衡 pilot 上观察到的覆盖率、恶意召回、正常误报和风险类型召回，在官方 556 条固定子集上是否仍然成立？
- 本轮只改变样本集合与样本量，不修改 Cisco 版本、分析器、策略、标签映射或指标定义。
- 90 条 pilot 是人为平衡样本；556 条官方子集分布不同，因此只比较方向与稳定性，不把指标差值解释为单一性能提升或下降。
- 官方榜单用 Cisco 原生 `actual_safe` 做二分类；本系统使用统一策略层 `ALLOW/REVIEW/BLOCK`。两者不等价，官方 Cisco 榜单值只作外部背景，不作同口径复现声明。
- 主指标继续采用 strict macro F1；补充报告统一策略层的 loose non-normal 二分类 precision/recall/F1/FPR。

## 3. 数据身份

- SkillTrustBench 数据提交：`762d5388b3a047b26df9679582af868a0e5b2c8f`
- 官方结果仓库提交：`326ec286d082199cb270b25b8b4fc93c8762281e`
- 官方子集文件 SHA-256：`dff7621ffcc7a42f1a8ff64c8e47d2fafc1cd332431fd533be88bb684aaa6843`
- 子集 ID 按“排序 ID + LF + 末尾换行”复算哈希：`903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2`
- 复算结果与同一提交的榜单记录完全一致。

## 4. 冻结项

- Cisco Skill Scanner 本地可执行文件及其 SHA-256。
- 命令模板：`skill-scanner scan <case_dir> --format json --output-json <temp> --compact`。
- 仅允许 `static_analyzer`、`bytecode`、`pipeline` 三类本地分析器。
- 策略文件：`config/admission_policy.yaml`，运行时记录 SHA-256。
- 标签映射：ALLOW→normal、REVIEW→suspicious、BLOCK→malicious、UNKNOWN→abstain。
- failed/UNKNOWN 在严格指标中按 abstain 错误计，不重试、不改宽松解析参数。
- 不执行、不导入、不安装样本；不开启 LLM、云上传、VirusTotal 或行为分析。

## 5. 指标与输出

- 必报：coverage、failure rate、strict/covered macro F1、malicious recall/FNR、non-normal recall、normal FPR。
- 风险切片：T01–T09 support、detected、recall。
- 补充二分类：precision、recall、loose F1、FPR 与 TP/FP/FN/TN。
- 工程指标：中位/P95/最大耗时、扫描完成数、abstain 数、样本扫描前后 tree hash。
- 错误清单：false positives、malicious false negatives、全部三分类错误。
- 最终报告：`docs/M2_SKILLTRUSTBENCH_OFFICIAL_10PCT_REPORT.md`。

## 6. 资源预算与停止条件

- Windows 本地 CPU 顺序扫描，不使用 Docker、云服务器或 GPU。
- 参考 90 条实验约 4 秒/条，预计 556 条约 35–45 分钟；运行上限 75 分钟。
- 每条超时 150 秒；实现断点续扫，已完成前缀必须通过 ID、契约和 tree hash 复核。
- 任一停止条件：样本 tree hash 改变、出现未知/外部分析器、数据/策略/指标契约哈希漂移、75 分钟内无合理进度。
- 单条普通解析失败不停止整批；记录为 UNKNOWN/abstain 并继续。

## 7. 成功标准

- minimum：556/556 均产生终态，所有样本扫描前后 hash 不变。
- solid：指标、混淆矩阵、错误切片、运行清单和复现命令完整，自动测试通过。
- maximum：形成可直接汇报的对照结论，并把误报/漏报优先级转化为下一轮自研规则任务。

## 8. 实际结果与决策

- 556/556 产生终态：546 completed、7 个 Cisco RuntimeError、3 个 Defender 阻断 abstain。
- coverage 98.20%，strict macro F1 0.4977，malicious recall 72.28%，normal FPR 24.70%。
- 统一策略层 loose precision 87.94%、recall 76.67%、F1 81.92%。
- 553 条可读样本扫描前后 tree hash 无变化；只观察到冻结允许的三个本地静态分析器。
- 首次运行完成 529 条后因 Defender 隔离文件缺失停止；断点恢复复核全部前缀后完成剩余 27 条。
- 8 个输出身份、指标与错误切片独立复算通过；最终测试 `71 passed`。
- 结论：`accepted_with_caveats`。工程链路可作为静态准入基线，但 91 条风险筛查漏报说明不能独立作最终安全裁决。
- 下一路由：优先分析 wild real-world、crypto_wallet、T06、T09、T05 漏报，再做上下文误报抑制和最小动态验证闭环。

## 9. 全量 5,520 条追加复核（2026-08-14 至 2026-08-15）

- run id：`2026-08-14-skilltrustbench-full-cisco-parallel-v1`。
- 仅将数据范围从官方 10% 扩大到完整 audited v1.0，并将执行方式改为 4 路有界并发；扫描器、策略、标签映射、失败闭锁和指标定义保持不变。
- 数据标签：normal 1,643 / suspicious 1,014 / malicious 2,863；排序 ID SHA-256 为 `99ed4644…b4a1`。
- 安全导入 5,520 条：5,451 条可扫描，61 条被端点防护阻断，8 条因 Windows 路径不兼容而只能保留归档身份。
- 5,520/5,520 产生终态：5,372 completed、148 abstain；abstain 包含 EndpointProtectionBlocked 61、PlatformPathIncompatible 8、RuntimeError 79。
- coverage 97.32%、strict macro F1 0.5090、malicious recall 71.11%、normal FPR 28.67%；策略层 precision 86.43%、recall 77.38%、loose F1 81.65%。
- 四路并发活跃墙钟 145.43 分钟，吞吐 37.96 条/分钟；所有可扫描样本 before/after tree hash 一致。
- 556 条重叠清单中，546 条双方均完成 Cisco 扫描；忽略绝对目录差异后决策与规则集合 0 差异，终态 0 差异。
- 最弱切片：wild_real_world 38/242（15.70%）、T06 42/96（43.75%）、T09 752/1120（67.14%）。
- 独立验收、73 项后端测试和 Markdown 报告通过；结论继续为 `accepted_with_caveats`。
- 下一路由：将全量结果作为当前最终评测证据，不再直接据此反复调参；另建开发/回归边界后开展 wild_real_world 语义增强和最小动态验证。

## 10. 开发集、回归集与缺口分析（2026-08-15）

- 将全量运行冻结为 `skilltrustbench-v1.0-full5520-cisco-static-v1`，冻结清单 SHA-256 为 `e4ed096b…17e4`。
- 建立 120 条开发集：60 条漏报、40 条正常误报、20 条正确对照；ID 清单 SHA-256 为 `1f9aad62…e383`。
- 建立 600 条封存回归集：normal/suspicious/malicious 各 200 条；ID 清单 SHA-256 为 `cd83b4f4…c07d`。
- 开发与回归零重叠；回归抽样未使用扫描结果，本轮未打开回归样本正文。
- 只读分析 120 条开发样本，前后 tree hash 全部一致，没有保存正文或代码片段。
- 路由结论：39 条新增静态规则、41 条证据关联、9 条语义复核、8 条规则校准、2 条策略分离、1 条动态验证、20 条正确对照。
- 第一实现批次：下载—解码—执行链、T06 持久化规则、声明—行为—敏感数据流关联。
- 规则与提示词在开发集冻结后，只允许对 600 条回归集做一次聚合配对评测；不得查看回归样本正文进行调参。
- 详细报告：`docs/M3_SKILLTRUSTBENCH_DEV_REGRESSION_AND_RULE_GAPS.md`。

## 11. Aegis Static v1 第一批规则实现（2026-08-16）

- 新增独立的 `aegis-static-v1` 增强层，不修改 Cisco 适配器与原始 Finding。
- 实现远程管道执行、下载—解码—执行、粘贴站载荷、内嵌载荷、不完整远程执行链，以及计划任务、系统服务、启动位置写入和不完整持久化证据规则。
- 完整攻击链或明确持久化为 `CRITICAL/BLOCK`；未证明数据流或自动执行载荷的证据为 `MEDIUM/REVIEW`。
- 三轮语义校准和一次复杂度加固均保留独立证据；最终 v4 在 36 条目标漏报中补出 21 条，T06 为 12/12，20 条正确对照零回退，50 条 normal 样本零决策升级。
- Aegis 平均耗时 17.27 ms/条，后端完整测试 `89 passed`；安全/风险预置 Skill 端到端结果保持 `ALLOW/BLOCK`，并均记录 Aegis analyzer 身份。
- 600 条回归集内容仍未打开。下一步实现声明—行为—敏感数据流关联，冻结第二批规则后再进行一次封存回归评测。
- 详细报告：`docs/M3_AEGIS_STATIC_V1_IMPLEMENTATION_AND_DEV_REPORT.md`。

## 12. Aegis Network Context v1 旁路证据（2026-08-18）

- 新增独立 `aegis-network-context-v1`，只追加 `INFO` Finding，不修改 Cisco Finding，不改变准入决策。
- 关联 `SKILL.md` 网络/外发/鉴权声明与 GET、POST、SDK 封装、敏感来源和外发 sink；敏感流只证明 80 行窗口共现，明确标注数据流未证实。
- 仅使用 16 条 `fp_network_context` 与 20 条正确对照，共 36 条开发样本；600 条回归集打开数为 0。
- 最终 v3：网络误报上下文覆盖 16/16，其中 15 条明确声明、1 条未声明；12 条有直接原语、3 条为 SDK/封装、1 条为 mock/local-only。
- 上下文加入前后决策 36/36 不变，正确对照 20/20 不变，与 Aegis Static v4 逐案等价。
- 平均耗时 12.78 ms/条，最大 35 ms；完整测试 `100 passed`；安全/风险预置保持 `ALLOW/BLOCK`。
- 下一步按相同 INFO-only 原则实现文件系统声明—实际读写—敏感路径上下文。
- 详细报告：`docs/M3_AEGIS_NETWORK_CONTEXT_V1_REPORT.md`。

## 13. Aegis Filesystem Context v1 开发实验（2026-08-18）

- run id：`2026-08-18-aegis-filesystem-context-dev-v1`；实验等级为 `auxiliary/dev`。
- 选定思路：新增独立 INFO-only 文件系统上下文层，把 `SKILL.md` 中的文件读写声明与实现中的实际读写、工作区普通路径、敏感路径及覆盖/删除/递归修改行为关联；不修改 Cisco Finding，不改变统一策略门禁。
- 研究问题：在不降低或抑制既有告警的前提下，是否能为 8 条 `fp_filesystem_context` 提供可核验的声明—行为—路径上下文，并保持 20 条正确对照及 Aegis Static v4 决策完全不变？
- 零假设：新增上下文无法覆盖目标文件系统误报，或会产生非 INFO Finding、决策漂移、对照回退或样本哈希变化。
- 备择假设：8/8 目标样本产生可解释上下文，28/28 决策不变、20/20 对照不变、Aegis Static v4 逐案等价，且回归集打开数为 0。
- 数据与基线：固定开发/回归划分 `2026-08-15-skilltrustbench-dev120-regression600-v1`；只选择 8 条文件系统误报和 20 条正确对照；Cisco 全量冻结基线与 Aegis Static v4 只读；网络上下文 v3 保持不变。
- 关键指标：目标上下文覆盖数；已声明/未声明读写；只读/写入；工作区或普通路径/敏感路径；覆盖、删除、递归修改；非 INFO Finding 数；决策变化数；对照变化数；Static v4 等价差异；样本前后哈希；耗时；回归读取数。
- 证据阶梯：minimum=分析器可执行且所有 Finding 为 INFO；solid=8/8 目标有上下文、28/28 决策不变、20/20 对照不变、测试通过并形成完整运行产物；maximum=接入 API、预置样本验证、文档和交接材料同步。
- 显著性计划：本轮是固定 8 条开发诊断样本的机制验证，不主张总体性能提升，不做显著性检验。
- 停止条件：任一 Finding 非 INFO、样本树哈希变化、Static v4 漂移、访问回归样本正文或出现样本执行/导入/安装行为。
- 放弃条件：在不引入样本特化规则的前提下无法为多数目标样本形成一般化上下文，或必须改变门禁才能得到表面改善。
- 最强替代解释：目标覆盖可能只说明 Cisco 的文件访问告警普遍命中文档已声明的正常能力，并不证明这些 Skill 安全，也不等于实际误报率下降。

### 13.1 最小代码变更图

| 路径 | 计划变更 | 目的 | 主要风险 |
|---|---|---|---|
| `backend/analyzers/filesystem_context.py` | 新增有界只读上下文分析器 | 关联声明、读写、路径与高风险修改 | 正则误归类、把共现误称为数据流 |
| `backend/analyzers/__init__.py`、`backend/app.py` | 接入统一 Finding 与健康状态 | 让上传扫描显示上下文证据 | 意外改变策略决策 |
| `backend/tests/test_filesystem_context.py` | 增加规则、边界和集成测试 | 证明 INFO-only、复杂度受限、决策不变 | 测试只覆盖合成样本 |
| `tools/evaluation/run_filesystem_context_development.py` | 评测固定 28 条开发样本 | 产出逐案结果、指标、哈希和环境清单 | 与既有基线不可比 |
| `artifacts/experiment/2026-08-18-aegis-filesystem-context-dev-v1/` | 保存合同、日志、指标和清单 | 可复现、可审计 | 输出覆盖或事后重构 |

### 13.2 执行路径与恢复

- smoke：运行文件系统分析器单元测试，确认规则结构、INFO-only 和策略不变。
- main：使用项目固定 Python 执行 `tools/evaluation/run_filesystem_context_development.py`，一次处理 28 条固定开发样本，不读取回归内容。
- validation：运行完整后端测试；核对输出哈希、必需指标、样本前后树哈希、Analyzer ID 与预置 Skill 端到端决策。
- 预计预算：实现与测试 1—2 小时；28 条只读上下文评测预计数秒，不使用 GPU、Docker、网络或云服务。
- 安全加速：复用 network context 的文件读取上限与既有冻结 parent/static 结果；不重新运行 Cisco 全量扫描。
- 恢复策略：若 smoke 暴露规则问题，只修改文件系统分析器及对应测试后使用新 run id 重跑；若 Static v4 或数据哈希不一致，立即停止并回到最近可解释状态。
- 环境限制：当前未提供技能文档指定的 `bash_exec`、`artifact.record_main_experiment` 和 memory 接口，因此使用项目内等价的不可覆盖运行目录、`run.log`、JSON manifest、SHA-256 与 Markdown 总结留痕。

### 13.3 预期输出与下一路由

- 运行输出：`per_case_context.jsonl`、`metrics.json`、`evaluation_summary.json`、`run_manifest.json`、`run.log`、`summary.md`、`claim_validation.md`。
- 成功后：冻结 Filesystem Context v1，下一步开发 command context INFO-only 证据；失败则只在 8 条目标开发样本上校准并记录新 run id。
- 检查表：`artifacts/experiment/2026-08-18-aegis-filesystem-context-dev-v1/CHECKLIST.md`。

### 13.4 实际结果与决策

- v1 完整运行但声明识别为 2/8，且存在文档示例行为化和重复路径 Finding，保留为校准父实验，不作为冻结版本。
- v2 只调整通用声明词形、源文件行为边界和 Finding 聚合；最终覆盖 8/8，声明/未声明 7/1。
- 28/28 决策不变，20/20 对照不变，Static v4 差异 0，样本哈希差异 0，回归读取 0。
- 平均耗时 15.32 ms、最大 53 ms；完整后端测试 `112 passed`；真实 Cisco BLOCK 演示保持 BLOCK。
- 结论为 `supported_on_development_set`，只支持开发集上的解释机制，不支持误报率下降或样本安全声明。
- 最终证据：`artifacts/experiment/2026-08-18-aegis-filesystem-context-dev-v2/`；下一路由为 command context INFO-only。

## 14. Aegis Command Context v1 开发实验（2026-08-18）

- run id：`2026-08-18-aegis-command-context-dev-v1`；实验等级为 `auxiliary/dev`。
- 选定思路：新增独立 INFO-only 命令上下文层，区分命令能力声明、仅导入未调用、参数数组/非 shell 调用、shell 字符串调用、固定/动态可执行文件、参数来源、安全测试夹具和危险命令；不重复 Aegis Static 的风险升级。
- 研究问题：能否为 6 条 `fp_command_context` 生成与其真实机制相符的解释证据，同时保持 20 条正确对照、Static v4 和当前统一门禁完全不变？
- 零假设：上下文不能覆盖目标样本，或把仅导入/测试载荷误称为真实执行，或产生非 INFO Finding、决策漂移、对照回退、样本变化或回归泄漏。
- 备择假设：6/6 目标具有上下文，26/26 决策不变、20/20 对照不变、Static v4 逐案等价、样本哈希不变、回归读取为 0。
- 数据与基线：固定划分 `2026-08-15-skilltrustbench-dev120-regression600-v1`；只选 6 条命令误报和 20 条正确对照；Cisco 全量冻结基线、Static v4、Network Context v1、Filesystem Context v1 均保持只读/不变。
- 关键指标：目标覆盖；声明/未声明；仅导入；参数数组/非 shell；shell 字符串；固定/动态可执行文件；用户/环境/文件参数来源共现；安全测试夹具；只读业务工具；危险命令类别；非 INFO 数；决策变化；对照变化；Static v4 差异；样本哈希；耗时；回归读取数。
- 证据阶梯：minimum=分析器可执行且全部 INFO；solid=6/6 目标有机制上下文、26/26 决策不变、20/20 对照不变、测试和证据包完整；maximum=真实 Cisco 端到端验证及文档同步。
- 显著性计划：固定 6 条开发诊断样本的机制验证，不主张总体性能提升，不做显著性检验。
- 停止条件：任一 Finding 非 INFO、样本哈希变化、Static v4 漂移、访问回归正文，或执行/导入/安装样本。
- 放弃条件：必须按 case ID/产品名硬编码才能覆盖，或必须改变门禁才能得到表面改善。
- 最强替代解释：命令上下文可能只提高可解释性，并不能证明被 Cisco 阻断的 normal 样本安全，也不代表独立测试误报率下降。

### 14.1 最小代码变更图

| 路径 | 计划变更 | 目的 | 风险 |
|---|---|---|---|
| `backend/analyzers/command_context.py` | 新增有界命令上下文分析器 | 区分声明、调用方式、参数来源、测试与危险命令 | 把字符串/示例误称为真实执行 |
| `backend/analyzers/__init__.py`、`backend/app.py` | 接入统一 Finding、扫描链与健康状态 | 让 API 显示上下文证据 | 意外改变门禁 |
| `backend/tests/test_command_context.py` | 合成、边界、复杂度和集成测试 | 验证 INFO-only 与机制分类 | 合成覆盖不足 |
| `tools/evaluation/run_command_context_development.py` | 固定 26 条开发评测 | 输出逐案证据、指标、哈希与环境清单 | 与基线不可比 |
| `artifacts/experiment/2026-08-18-aegis-command-context-dev-v1/` | 保存计划、日志、指标和 manifest | 可复现和可审计 | 输出被覆盖 |

### 14.2 执行与恢复

- smoke：运行命令上下文专项测试，验证仅导入、argv、shell、测试夹具、参数来源和危险命令。
- main：项目固定 Python 执行 26 条开发评测，不读取回归内容。
- validation：完整后端测试、真实 Cisco BLOCK 演示、输出和源码 SHA-256 复核。
- 预算：实现与验证约 1—2 小时；评测预计数秒，不使用 GPU、Docker、云服务或样本网络。
- 恢复：首轮若分类与冻结元数据或只读人工核对明显冲突，保留 v1 原始证据，仅修改通用规则并使用新 run id。
- 工具限制：当前没有技能指定的 `bash_exec`、artifact 和 memory 接口，继续使用不可覆盖本地运行目录、日志、manifest、SHA-256 和 Markdown 总结等价留痕。

### 14.3 输出与下一路由

- 必需输出：`per_case_context.jsonl`、`metrics.json/md`、`evaluation_summary.json`、`run_manifest.json`、`artifact_manifest.json`、`run.log`、`bash.log`、`summary.md`、`claim_validation.md`。
- 成功后：冻结三个 INFO-only 上下文族，评估是否先做小型动态审计 fixture，还是冻结规则后一次性运行 600 条回归配对评测。
- 检查表：`artifacts/experiment/2026-08-18-aegis-command-context-dev-v1/CHECKLIST.md`。

### 14.4 实际结果与决策

- v1 完整运行并达到 6/6 覆盖、5/5 机制和 26/26 决策不变，但逐案复核发现 `case_00458` 的普通 JavaScript 模板字符串被误解释成 shell 引号变量；v1 原始产物保留为校准父实验。
- v2 只把 quoted-shell 规则收紧为“同一源文件内存在 shell 字符串调用或 shell 脚本”；目标 quoted-shell 计数从 2 降至 1，其余关键机制、逐案决策和基线均保持不变。
- 最终 v2 覆盖 6/6、机制检查 5/5；26/26 决策不变，20/20 正确对照不变，Static v4 差异 0，样本哈希差异 0，回归读取 0。
- 平均耗时 20.58 ms、最大 91 ms；命令专项测试 14 passed、完整后端测试 `126 passed`；真实 Cisco BLOCK 演示保持 BLOCK，样本哈希不变。
- 结论为 `supported_on_development_set`，只支持开发集上的解释机制，不支持误报率下降、样本安全或真实命令数据流声明。
- 最终证据：`artifacts/experiment/2026-08-18-aegis-command-context-dev-v2/`；下一路由为最小安全动态 fixture，最终决策继续不变。

## 15. 最小安全动态 Fixture v1 开发实验（2026-08-18）

- run id：`2026-08-18-safe-dynamic-fixture-dev-v1`；实验等级为 `auxiliary/dev`。
- 选定思路：先实现独立命令行的协作式 Python 动态观测器，只运行 SHA-256 锁定的自建良性 fixture。通过 Python audit hook 记录进程、stdin、环境变量、工作区文件和本机回环网络事件，并在事件发生前拒绝工作区外写入、非回环连接及非白名单可执行文件。
- 用户约束：Windows + Python；网络仅 `127.0.0.1`；不运行 SkillTrustBench 或任何第三方样本；不接入门禁；所有动态证据为 INFO；最终决策不变。
- 研究问题：能否在没有 Docker、GPU、云服务器和系统级沙箱的条件下，为自建良性 fixture 生成可核验、脱敏、可复现的动态证据，并保持明确的 fail-closed 安全边界？
- 零假设：观测器不能完整捕获预期事件，或发生未授权文件/网络/进程行为、超时、原始输入泄露或把协作式观测夸大成不可信样本沙箱。
- 备择假设：3/3 fixture 完成、全部预期事件满足、策略违规 0、超时 0、非 INFO 证据 0、原始 token 泄露 0；单元测试证明非回环、工作区外写入和非白名单进程在动作前被拒绝。
- 基线：静态链冻结在 `2026-08-18-aegis-command-context-dev-v2`；本轮是互补的动态机制验证，不与静态准确率或误报率做数值比较。
- 数据：无外部数据集；仅 `tools/dynamic/fixtures/` 中的三份自建良性脚本。开发集、回归集和 Cisco 样本读取数均为 0。
- 关键指标：fixture 完成数、预期事件检查、策略违规、超时、子进程/argv、stdin、环境变量、文件读写、回环连接、服务端接收、非 INFO 证据、原始 token 泄露、耗时和受保护数据读取数。
- 证据阶梯：minimum=单 fixture 可运行且输出脱敏事件；solid=3/3 fixture、全部防护测试和证据 manifest 通过；maximum=接入平台 API/UI，本轮不做。
- 显著性计划：这是三类机制的确定性工程验证，不主张总体检测性能提升，不做统计显著性检验。
- 停止条件：任何第三方/数据集样本被执行或读取、任何外网连接到达 OS、任何工作区外写入、原始测试 token 进入结果、策略违规未 fail-closed、最终门禁被修改。
- 放弃条件：要满足当前安全合同必须安装驱动、关闭端点防护、使用管理员权限或执行不可信样本。
- 最强替代解释：成功只能证明自建、哈希锁定 Python fixture 的协作式观测契约可用，不能证明形成了可安全执行恶意 Skill 的沙箱，也不能观测未注入 bootstrap 的后代进程内部行为。

### 15.1 最小代码变更图

| 路径 | 计划变更 | 目的 | 风险 |
|---|---|---|---|
| `backend/dynamic_audit/policy.py` | 路径、网络和可执行文件 fail-closed 校验 | 在动作前拒绝越界 | Python 层可被原生代码绕过 |
| `backend/dynamic_audit/bootstrap.py` | 安装 audit hook 与 stdin/env 脱敏观测 | 生成统一动态事件 | 只覆盖当前 Python 进程 |
| `backend/dynamic_audit/runner.py` | 校验 fixture 哈希、净化环境、超时运行和聚合证据 | 可复现批量执行 | 错误配置造成误放行 |
| `tools/dynamic/fixtures/*.py` | 三个自建良性机制 fixture | 覆盖进程/IO、文件、回环网络 | 不代表真实恶意样本 |
| `config/safe_dynamic_fixtures.json` | 冻结脚本哈希、预期事件和资源上限 | 防止任意脚本进入执行面 | 代码更新需同步哈希 |
| `tools/dynamic/run_safe_fixture_audit.py` | 独立 CLI 与证据导出 | 暂不扩展平台攻击面 | 还没有 API/UI |
| `backend/tests/test_safe_dynamic_audit.py` | 防护、脱敏、集成和 CLI 测试 | 验证 fail-closed | 合成测试覆盖有限 |

### 15.2 执行与恢复

- smoke：先运行 policy 和单 fixture 测试，确认非回环/越界写/非白名单进程的校验函数在不发起真实危险动作时拒绝。
- main：项目固定 Python 执行三份良性 fixture，工作目录限定在本次不可覆盖 run 目录，网络服务器只绑定 `127.0.0.1` 随机端口。
- validation：完整后端测试、结果 schema、预期事件、token 脱敏、源码/fixture/证据 SHA-256 复核。
- 预算：预计数秒；每 fixture 超时 5 秒；不使用 GPU、Docker、云服务、管理员权限或互联网。
- 恢复：smoke 若暴露实现问题，只修改一个安全层变量并保留失败日志；主运行一旦生成受保护输出，不覆盖，改用新 run id。
- 工具限制：`bash_exec`、artifact、memory 接口不可用；使用不可覆盖本地目录、日志、manifest 和 SHA-256 等价留痕。

### 15.3 输出与下一路由

- 必需输出：`per_fixture.jsonl`、`events.jsonl`、`metrics.json/md`、`evaluation_summary.json`、`run_manifest.json`、`artifact_manifest.json`、`run.log`、`bash.log`、`summary.md`、`claim_validation.md`。
- 成功后：形成动态证据 v1 契约和限制说明，再决定是否只把“运行自建 fixture”能力接入平台管理员接口；仍不执行第三方样本。
- 检查表：`artifacts/experiment/2026-08-18-safe-dynamic-fixture-dev-v1/CHECKLIST.md`。

### 15.4 实际结果与决策

- 两轮 smoke 均安全闭锁进程 fixture，依次确认 Windows audit 的 `executable=None` 和 exact command-line string 语义；最终以父 Runner 生成的完整命令行 SHA-256 做唯一匹配，专项测试 8/8 通过。
- v1 主运行达到 3/3 fixture、7/7 机制和全部负面指标 0；封口审查仍发现相对路径/cwd 与链接边界需要显式收紧，v1 原始结果保留为校准父运行。
- v2 固定 fixture、哈希和指标，只改为按实际 cwd 解析相对路径、限制 chdir、拒绝软/硬链接，并准确标记 Windows command-line 证据；专项测试增至 10/10。
- 最终 v2 为 3/3、7/7；策略违规、超时、解析错误、非 INFO、token 泄露、受保护样本读取/执行、互联网连接和决策变化均为 0。
- 平均耗时 219.33 ms、最大 289 ms；完整后端测试 `136 passed`；证据正文中三个原始测试 token 和受保护样本路径引用均为 0。
- 结论为 `supported_on_safe_fixtures`，只支持自建哈希锁定 Python fixture 的协作式动态观测，不支持不可信代码沙箱或恶意检出率声明。
- 最终证据：`artifacts/experiment/2026-08-18-safe-dynamic-fixture-dev-v2/`；下一路由为管理员专用内置 fixture 接口，不接受任意脚本或上传代码。

## 16. 动态 Marker 源到汇证据核心 v1（2026-08-22）

- 选定思路：复现论文 Marker-Based Taint/SandScope 的最小工程核心，以静态 Finding 生成 Trigger Plan，用政企假数据 Marker 证明指定敏感源是否到达受控汇点；本地模型暂不进入最终判定。
- 基线：静态回归 `2026-08-22-static-audit-regression600-v1` 只读，本轮是互补机制实验，不做数值比较，不改变最终决策。
- 数据与安全：只执行 1 个自建、SHA-256 锁定良性 fixture；只连接父进程 `127.0.0.1` 随机端口；第三方、回归和公开恶意样本读取/执行均为 0。
- v1：1/1 fixture、3/3 事件、1 条 Base64 witness 和全部安全负面指标 0，但关联函数没有限制 witness profile 必须属于 Trigger Plan；保留为校准父运行。
- v2：增加计划内 profile 约束和计划外 Marker 反例；计划内得到 confirmed，计划外只能 observed，运行失败为 inconclusive。
- 最终结果：1/1 fixture、3/3 事件、1 条 `official_document` Base64 witness、`confirmed`；Marker 泄露、策略违规、超时、外网、受保护样本读取/执行和静态决策变化均为 0。
- 验证：动态专项测试 `22 passed`，完整后端测试 `270 passed`，证据包包含命令、环境、源码/fixture 哈希、指标、日志和关联结果。
- 结论：`supported_on_controlled_fixture`，只证明受控 Marker 源到汇和静态引导关联机制，不证明第三方代码沙箱、恶意检出率或真实世界泛化。
- 下一路由：D2 Docker 安全执行后端；当前 `docker` 命令不可用，在安全门通过前不得执行第三方样本。

## 17. D2 Docker 安全执行底座（2026-08-22）

- 研究问题：能否在不下载镜像、不执行第三方样本和不改变静态决策的条件下，用 Docker 建立 create→inspect→start→cleanup 的失败闭锁后端？
- 镜像：固定本机已有 `python:3.12-slim` 的 repo digest 和 image ID，`pull=never`。
- 配置门：镜像 4 项，容器 inspect 24 项；网络 none、只读根、UID/GID 65532、cap-drop ALL、NNP、PID/内存/CPU、tmpfs、单文件只读挂载、无 Docker Socket。
- 运行门：12 项；实际验证 CapEff=0、NoNewPrivs=1、Seccomp=2、根/输入写入拒绝、workspace/tmp 写入成功、网络仅 lo。
- v1：40/40 和清理真实通过，但 API 字段误记为字符串 None，保留为校准父运行。
- v2：修正 ApiVersion 字段，增加成功、非法 ID 和启动超时清理测试；真实 Engine 29.7.2 / API 1.55。
- 最终结果：4/4 + 24/24 + 12/12 = 40/40；fixture 1/1；策略违规、超时、残留、第三方样本、互联网、镜像拉取和决策变化均为 0；运行约 1.06 秒。
- 验证：Docker 专项 `26 passed`，后端完整 `296 passed`，独立标签查询容器残留 0。
- 结论：`supported_on_controlled_fixture`；只支持当前固定镜像与自建 probe 的安全门，不支持容器逃逸或第三方样本安全声明。
- 下一路由：自建 MCP 协议 fixture 与 Marker witness；D2-B 的 strace/文件差分/内部 sinkhole 继续作为后续遥测增强。

## 18. P0-1 可移植启动与换机复现（2026-08-24）

- run id：`2026-08-24-portable-startup-dev-v1`；实验等级为 `auxiliary/dev`。
- 选定思路：保留现有项目内两个 Cisco 隔离运行时目录约定，移除启动脚本中的个人绝对路径；新增共享命令发现、分层 preflight 和固定提交的在线/离线运行时重建入口。
- 用户要求：先推送两份评委审查文档，再按 M5 计划优先完成 P0-1；每一步说明实际动作。
- 研究问题：仓库能否在不依赖 `C:\Users\23684` 或 Codex 内置运行时路径的条件下，发现项目运行时和 Node 包管理器，并在缺失组件时给出可执行的重建指引？
- 零假设：移除硬编码后当前机器无法启动，或 preflight 不能稳定区分必需静态能力与可选/强制动态能力，或重建流程不能固定 Cisco 来源与版本。
- 备择假设：启动脚本个人路径命中为 0；默认 preflight 必需项全部通过；修改 `USERPROFILE` 且从 PATH 移除 Codex pnpm 后仍能通过 Corepack 发现前端工具；完整后端/前端验证保持通过。
- 基线：提交 `3d98c85`，固定本机启动、后端 324 passed、前端 10 passed、生产构建通过；静态/动态检测规则、策略和评测结果保持只读。
- 主指标：个人绝对路径命中数、preflight 必需项失败数、模拟异用户 preflight 结果、启动健康状态、后端/前端测试与构建结果。
- 停止条件：必须修改 Cisco/Aegis 检测逻辑、放宽 Docker/动态安全边界、覆盖现有运行时或向仓库提交第三方二进制。
- 放弃条件：固定 Cisco 提交无法从官方仓库构建，且许可证或依赖约束不允许形成可说明的在线/离线恢复路径。
- 最强替代解释：当前机器成功仍不等于全新 Windows 已验收；本轮先达到可移植代码与模拟异用户 solid 证据，真正干净虚拟机验收保留为 P0-5 发布门。

### 18.1 最小代码变更图

| 路径 | 计划变更 | 目的 | 风险 |
| --- | --- | --- | --- |
| `scripts/portable_runtime.ps1` | 统一发现 pnpm/Corepack 与 Docker CLI | 消除个人路径并避免脚本间发现逻辑漂移 | PowerShell 版本和参数拼接差异 |
| `preflight.ps1` | 检查 Cisco 版本、策略、前端、写权限、令牌、Docker 和固定镜像 | 启动前给出机器可读/人可读结论 | 把可选动态能力误设为静态阻断 |
| `start_demo.ps1` | 使用共享发现和冻结 lockfile 安装 | 换用户路径仍可构建和启动 | Corepack 首次使用可能需要联网 |
| `bootstrap_runtimes.ps1` | 固定官方仓库、提交、Python 版本、哈希锁和 wheel 安装 | 从空仓库重建两个 Cisco 运行时 | Python 3.13/Rust 首装耗时较长 |
| `backend/tests/test_portable_startup.py` | 静态契约和模拟异用户 preflight | 防止个人路径回归 | 仍不是独立干净机器 |
| `QUICKSTART.md` | 区分在线重建、离线 wheel 和最终验收 | 让本科生可按步骤恢复 | 文档与脚本后续漂移 |

### 18.2 执行与验收

- smoke：运行脚本静态契约测试和默认 preflight；确认当前运行时不会被修改。
- main：把 `USERPROFILE` 指向项目内临时目录，从 PATH 删除 Codex pnpm 路径，仅保留系统 Node/Corepack，再运行 JSON preflight。
- integration：使用改造后的 `start_demo.ps1 -NoBrowser` 启动，核验 `/api/v1/health` 后安全停止。
- regression：后端完整测试、前端 API 测试与 frozen-lockfile 生产构建。
- 持久证据：`artifacts/experiment/2026-08-24-portable-startup-dev-v1/`，包含 preflight、模拟异用户结果、测试/构建摘要、manifest 和结论。
- 工具限制：当前没有 experiment 技能指定的 `bash_exec`、artifact 和 memory 接口，因此继续使用可用终端、不可覆盖证据目录、命令日志、manifest 和 SHA-256 等价留痕。
- 成功后：进入 P0-2 动态任务互斥、排队、重复提交保护和重启恢复；失败则保留当前可用启动状态，只修复具体的可移植性阻断。

### 18.3 实际结果与决策

- 活动启动文件的个人绝对路径命中为 0；使用脚本相对路径定位两套项目运行时。
- 静态 preflight 必需失败 0；Cisco Skill `2.0.13.dev3+g4dee90371`、MCP `4.8.2`、FastAPI、策略哈希、前端锁文件和写入探针全部通过。
- 完整重定向 `USERPROFILE/LOCALAPPDATA/APPDATA`，并从 PATH 移除 Codex pnpm 后，真实 Corepack pnpm 11.23.0 预检仍通过。
- 新增运行时重建脚本，固定官方来源、提交、Python 版本、哈希锁和 wheel 安装；现有运行时精确验证 2/2，不自动覆盖异常目录。
- 8000 端口被 Docker Desktop 占用时没有改动现有进程；启动脚本增加 `-Port`，在 8765 完成预检、构建、启动、v1 health 和停止。
- 无管理员令牌时 `-RequireDynamic` 失败闭锁；默认启动返回 `degraded`，不冒充动态就绪，静态功能可用。
- 验证为可移植专项 `5 passed`、后端完整 `329 passed`、前端 `10 passed`、冻结离线安装和生产构建通过。
- 结论为 `supported_on_current_machine_and_simulated_user`；真正洁净 Windows VM 从零复现未完成，保留为 P0-5。
- 固定证据：`artifacts/experiment/2026-08-24-portable-startup-dev-v1/`；下一路由为 P0-2 动态任务并发与重启恢复。

## 19. M5 P0/P1/P2 工程收敛（2026-08-24）

- 用户明确要求完成 M5 全部 P0/P1/P2 工程项，不包含 PPT、视频和答辩材料。
- 每个通过验收的里程碑可直接提交并推送到 `origin/dynamic-audit-v1`。
- 可引入必要开源依赖，但必须固定版本、核验来源/许可/哈希，不执行第三方不可信样本。
- P0-5 必须使用可证明虚拟硬件身份的真实洁净 Windows VM；Windows Sandbox 优先，但当前家庭版宿主不支持，允许 VirtualBox/VMware/QEMU/Hyper-V guest；本机目录、Docker/WSL 和异用户模拟均不作为最终证据。
- 详细顺序、退出门和 P0-2 验收合同见 `docs/M5_ENGINEERING_EXECUTION_PLAN.md`。
- 当前执行节点：P0-5 真实洁净 Windows VM 发布门；自动验收程序与本机非正式烟雾已通过，真实 VM 执行和证据冻结未完成；P0-4 已通过并冻结。

### 19.1 P0-2 实际结果

- 采用 SQLite 持久队列和单执行器；数据库原子认领是全局互斥真值，UI 只展示后端队列状态。
- 活动任务与 5 秒冷却窗口内的同类提交合并到原 ID；等待队列默认上限 4，超限结构化返回 429。
- 重启时 running 失败闭锁、queued 保留 FIFO；执行器未落终态由调度器补写失败，不遗留永久中间态。
- 验收：专项 14 passed、后端 335 passed、前端 10 passed、生产构建通过；规则、政策和 fixture 哈希未修改。
- 证据：`artifacts/experiment/2026-08-24-dynamic-queue-recovery-dev-v1/`。
- 结论边界：只证明单主机 SQLite 调度，不等价于多实例生产队列；下一节点为 P0-3 当前状态真值。

### 19.2 P0-3 实际结果

- 建立根 `CURRENT_STATUS.md` 作为能力、测试数、发布判断和下一项的唯一状态真值。
- 活动 README/启动/安全/API 入口全部指向该文件；7 月复现和旧评委/开发计划明确标为历史快照。
- 新增两级文档索引和 6 项防漂移测试；API 契约补齐 P0-2 队列字段、429 与恢复失败码。
- 验收：文档专项 6 passed、后端 341 passed、前端 10 passed、生产构建通过。
- 证据：`artifacts/experiment/2026-08-24-current-status-truth-dev-v1/`；下一节点为 P0-4 项目自身供应链卫生。

### 19.3 P0-4 实际结果

- Web Python、共享 Cisco/Aegis 运行时和前端直接依赖均形成精确版本与哈希/完整性锁；实际安装版本由 preflight 校验。
- 修复 Node `nanoid 3.3.16` 高危通告，并对共享运行时 17 个安全/兼容包应用哈希覆盖；实际 126 个 Python 包和 Windows x64 Node 安装图的当日已知漏洞为 0。
- 新增私有比赛许可、第三方声明和 152 组件 CycloneDX 1.6 项目 SBOM；许可越界、锁不匹配、已验证 Secret 和仓库卫生违规均为 0。
- Cisco 固定样本复现脚本新增失败闭锁 oracle，避免内部 pip-audit 无输出时被上游错误显示为 SAFE。
- 验收：自身供应链 gate 12/12、后端 348 passed、前端 10 passed、生产构建及 Cisco 固定样本冒烟通过。
- 证据：`artifacts/experiment/2026-08-24-project-supply-chain-hygiene-dev-v1/`；下一节点为 P0-5 真实 Windows VM 发布门。

## 20. M6 OpenClaw 安装前准入（2026-08-26）

- 选定路线：使用官方 `security.installPolicy`，实现不依赖 HTTP 的本地同步适配器；Web 平台只作为后续审计展示面。
- M6-1 已完成：protocol v1 校验、目录边界、扫描前后整树哈希、现有 Skill 静态流水线复用、决策映射、失败关闭、UTF-8 CLI 与配置示例。
- 现有规则、默认策略、全量基准和600条密封回归结果未修改。
- 自动测试：OpenClaw 专项22个用例；后端完整 `383 passed`。
- 真实自建固定样本：安全 Skill 为 allow，恶意外传 Skill 为 block；输入树均保持不变。
- 当前证据等级：`supported_on_local_adapter_and_controlled_fixtures`，尚未声称真实 OpenClaw 安装提交完成。
- 下一节点：M6-2，在本机配置 OpenClaw `security.installPolicy`，运行 `doctor --deep` 和 allow/warn/block/failure 四类安装闭环。
- 设计真值：`docs/M6_OPENCLAW_INSTALL_POLICY_DESIGN.md`。
- 运行证据：`artifacts/experiment/2026-08-26-openclaw-install-policy-v1/`。

### 20.1 M6-2 真实 OpenClaw 结果

- npm 稳定版 `2026.7.1-2` 真实完成隔离安全 Skill 安装；恶意 Skill 被 `CRITICAL 2 条` 阻断且残留0。
- 稳定版只接受 allow/block；增加显式 REVIEW→block 兼容模式后，中风险 Skill 被说明性阻断且残留0。
- 发现 `OPENCLAW_STATE_DIR` 不隔离 workspace，已改为强制设置 `agents.defaults.workspace`；首次测试目录可恢复移出，用户原工作区残留0。
- 隔离核验 Beta `2026.8.1-beta.3` 官方 npm SHA-512，但其 Windows ACL 门拒绝常见祖先目录，`doctor --deep` 安装策略项未全绿；不纳入比赛冻结依赖。
- 后端完整 `386 passed`；结论为 `supported_with_upstream_version_limits`。
- 下一节点：M6-3 准入审计、扫描进程环境白名单和部署前检查。

### 20.2 M6-3 准入审计与隔离加固

- 扫描子进程从空环境构建白名单，不再复制服务环境；真实用户目录由仓库缓存内合成 profile 替代。
- Cisco Skill、MCP 和 pip-audit 三条真实链均在白名单下完成；依赖链检出1个依赖中的14个漏洞。
- 安装策略新增最小化 SQLite 追加审计、UPDATE/DELETE 触发器、前序哈希链和独立校验工具；落库失败转为 block。
- 完整部署 preflight 校验固定版本/哈希、环境契约、策略、安全/恶意固定样本和2行审计链，结果 ready=true。
- 真实 CLI 两次耗时4420/4422ms，分别 allow/block，审计链头为 `0a14b264e6e87cb82db4b0ba11f68ec7397f7a96926e6af2815711f4bf1cb101`。
- 后端完整 `390 passed`；下一节点 M6-4 Plugin/MCP 安装包最小适配。
