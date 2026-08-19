# M3：SkillTrustBench 全量结果冻结、开发/回归划分与检测缺口分析

日期：2026-08-15  
父运行：`2026-08-14-skilltrustbench-full-cisco-parallel-v1`  
划分 ID：`2026-08-15-skilltrustbench-dev120-regression600-v1`

## 1. 本轮结论

本轮没有重新扫描、没有修改 Cisco 结果，也没有执行任何样本。已经完成三件事：

1. 将 5,520 条 Cisco 静态扫描固化为当前比较基线；
2. 建立 120 条可见开发集和 600 条封存回归集，二者零重叠；
3. 只读分析开发集文本，得到可执行的规则、证据关联、语义复核和动态验证任务。

120 条开发样本的建议路线为：

| 路线 | 样本数 | 含义 |
|---|---:|---|
| 新增确定性静态规则 | 39 | 已存在可定位的持久化、提权、不安全编码或下载执行特征 |
| 证据关联 | 41 | 单个 API/文件/进程行为不足以判恶，需要结合声明、敏感源和危险汇点 |
| 大模型语义复核 | 9 | 词法特征不足，重点判断描述—行为不一致、诱导和隐含意图 |
| 现有规则校准 | 8 | 文件类型或密钥样式规则需要占位符、用途和内容类型上下文 |
| 元数据策略分离 | 2 | 描述过长等质量问题不应直接等价为恶意 |
| 后续动态验证 | 1 | 当前静态文本不足以作可靠判断 |
| 正确对照 | 20 | 用于保护正常、可疑和恶意的已知正确行为 |

这意味着下一步不应继续无差别增加正则规则。最优路线是同时做两类增量：一类补高置信攻击链，另一类降低网络、文件和进程访问产生的上下文误报。

## 2. 全量结果如何冻结

冻结基线 ID：`skilltrustbench-v1.0-full5520-cisco-static-v1`。

| 指标 | 冻结值 |
|---|---:|
| 终态样本 | 5,520 / 5,520 |
| completed / abstain | 5,372 / 148 |
| coverage | 97.32% |
| strict macro F1 | 0.5090 |
| malicious recall | 71.11% |
| non-normal recall | 77.38% |
| normal FPR | 28.67% |
| 策略层 loose F1 | 81.65% |

冻结目录：`baseline/skilltrustbench_v1_0/full_cisco_static_v1/`。

- `json/metric_contract.json`：全量比较口径、实际指标和声明边界；
- `freeze_manifest.json`：原始结果、报告、数据清单、运行器、校验器和策略文件的大小及 SHA-256；
- `FREEZE_SHA256.txt`：冻结清单自身 SHA-256；
- `local_acceptance.json`：本地接受结论与限制；
- `provenance.json`：数据、扫描器、策略和运行路径。

`freeze_manifest.json` SHA-256 为 `e4ed096b3de5ed25a8397899906524f4f8a257ead380a07f273c661088bf17e4`。任何受保护文件发生字节变化，都不再是同一份冻结基线。

本基线属于“已验证工程基线”，不是预注册盲测。指标定义在首轮扫描前已经冻结，但完整 5,520 条的范围记录是在运行后固化；后续不能在同一全量数据上反复调参并声称得到无偏最终成绩。

## 3. 开发集与回归集

### 3.1 开发集：120 条

开发集使用全量扫描结果进行定向选择，因此允许查看和分析，只能用于工程开发。

| 组成 | 数量 |
|---|---:|
| wild_real_world 非正常漏报 | 24 |
| T06 系统持久化漏报 | 12 |
| T09 不安全编码漏报 | 12 |
| T05 越权访问与提权漏报 | 12 |
| 网络上下文正常误报 | 16 |
| 文件访问正常误报 | 8 |
| 进程/命令上下文正常误报 | 6 |
| 文件类型正常误报 | 4 |
| 密钥样式正常误报 | 4 |
| 描述/元数据正常误报 | 2 |
| 正确识别对照 | 20 |

标签分布为 normal 50、suspicious 22、malicious 48。开发集 ID 清单 SHA-256 为 `1f9aad62b52b21ce43ef408008b59f2b9ffda09a4d1df459b62f4e606d0fe383`。

### 3.2 回归集：600 条

回归集按 normal、suspicious、malicious 各 200 条组成。每类在排除开发集后，按 `SHA-256(seed + ':' + case_id)` 排序选择；没有使用父扫描的预测或错误类型进行挑选。

回归集只保存 ID、真值标签、风险标签、case tree SHA-256 和确定性排序值。本轮没有打开任何回归样本正文，回归集 ID 清单 SHA-256 为 `cd83b4f4251b23701fdd98b6b9d3899777ca41f9d573d4fb502ce3307f0cc07d`。

回归集的作用是检查改规则后是否退化，不是新的独立权威测试集。最终对外性能主张仍需要另一份没有参与设计的外部数据或比赛方隐藏测试。

## 4. 分析方法与安全边界

只对 120 条开发样本执行以下只读操作：

- 检查每个 case 的 tree SHA-256；
- 读取 `SKILL.md` 及脚本文本，不解析或加载样本模块；
- 将文本转换为规范化特征码，例如 `persistence_startup`、`privilege_escalation`、`network_client`；
- 分析 `SKILL.md` 是否声明网络、文件、进程、安全、权限或持久化能力；
- 输出特征计数和建议路线，不保存正文、代码片段、密钥或原始证据；
- 分析后再次检查全部 120 个 tree SHA-256。

结果：120/120 完成只读分析，样本 hash 变化为 0；回归样本正文打开数为 0。分析过程重复运行后，开发集、回归集、特征分析、汇总和清单等 6 个关键文件 SHA-256 全部一致。

特征码是规则设计线索，不是新的模型预测。它只能支持“下一步应该实现什么”的工程决策，不能直接当作新的准确率结果。

## 5. 结合全量扫描结果得到的优先级

### P0：补下载—解码—执行与持久化攻击链

全量数据最弱的业务切片是 `wild_real_world`：242 条非正常样本只检出 38 条，召回 15.70%。开发集选取的 24 条漏报包括：

| ground-truth pattern | 数量 |
|---|---:|
| `installer_dropper_base64` | 11 |
| `installer_dropper_curl_bash` | 5 |
| `glot_io_paste_dropper` | 5 |
| `cross_platform_installer_lure` | 2 |
| `embedded_base64_blob` | 1 |

建议先实现四个跨文件/跨步骤规则，而不是只匹配单个 `curl`、`requests` 或 Base64：

1. `REMOTE_FETCH_PIPE_SHELL`：远程获取与 shell/PowerShell 执行形成链路；
2. `REMOTE_FETCH_DECODE_EXECUTE`：下载、Base64/Hex 解码与执行形成链路；
3. `PASTE_SERVICE_PAYLOAD_EXECUTION`：paste/在线代码服务作为可变载荷源并进入执行汇点；
4. `EMBEDDED_BLOB_DECODE_EXECUTE`：Skill 内嵌大块编码数据经过解码后进入动态执行或进程启动。

T06 全量召回只有 43.75%。本次 12 条 T06 漏报全部属于 `PY_PYTHON_PERSIST`，其中 11 条能由当前特征直接路由到静态规则。建议新增：

- `PERSISTENCE_STARTUP_PROFILE_WRITE`：写入 shell profile、启动目录、注册表 Run 或 authorized_keys；
- `PERSISTENCE_SCHEDULED_TASK`：crontab、schtasks、Register-ScheduledTask 等；
- `PERSISTENCE_SERVICE_CREATE`：systemd、launchd、Windows service 创建；
- 关联约束：必须同时出现持久化目标与写入/创建动作，避免仅在说明文档中提到“service”就报警。

### P0：先降低三类高频正常误报

全量正常误报中，`TOOL_ABUSE_UNDECLARED_NETWORK` 涉及 164 条，`DATA_EXFIL_NETWORK_REQUESTS` 95 条，`DATA_EXFIL_JS_FS_ACCESS` 77 条。开发集只读分析显示：

- 16 条网络误报中，15 条在 `SKILL.md` 声明了网络能力；
- 8 条文件访问误报中，7 条声明了文件能力；
- 6 条进程/命令误报中，5 条声明了进程或开发工具能力；
- 4 条密钥样式误报都具有安全工具语境，不能只凭字符串形状判恶。

建议新增一个“声明—行为—数据流”证据关联层：

1. 从 `SKILL.md` 提取声明能力和允许目标；
2. 从脚本提取敏感数据源、危险转换和网络/文件/进程汇点；
3. 单独的正常 API 调用只记低级证据；
4. “未声明能力”或“敏感源→外发汇点”“网络获取→执行汇点”才升级；
5. 不进行全局降严重度，避免为了降低误报而扩大漏报。

### P1：补 T09 不安全编码与 T05 权限边界

12 条 T09 漏报中，9 条适合静态规则、2 条需要证据关联、1 条留给动态验证。主要模式为：

- `V_CONTEXT_LEAK` 3 条；
- `V_DESTRUCTIVE_NO_CONFIRM` 3 条；
- `V_WILDCARD_PERMS` 3 条；
- `V_MISLEADING_DESCRIPTION`、`V_PERSISTENT_SERVICE` 和无主模式各 1 条。

建议补：敏感上下文源到输出汇点的轻量污点关联、破坏操作缺少确认门禁、通配符/过宽权限以及描述—行为不一致检查。

12 条 T05 漏报主要为 `EX_COVERT_EXFIL` 5 条、`V_WILDCARD_PERMS` 3 条、`V_CONTEXT_LEAK` 2 条。T05 不能只靠 `sudo` 关键词检测，重点应是“任务所需权限”和“实际访问范围”的差异，以及凭据/环境/敏感文件到网络汇点的关联。

### P1：大模型只做结构化语义复核

优先送入语义复核的 9 条开发样本为：

`case_05621`、`case_05623`、`case_05731`、`case_05698`、`case_05637`、`case_05696`、`case_05539`、`case_03461`、`case_05381`。

建议大模型输入为脱敏后的声明、文件清单和特征图，输出固定 JSON：声明目的、实际能力、描述—行为差异、可能风险标签、引用的文件级证据和置信度。模型结论不能直接 `BLOCK`；高置信语义风险先进入 `REVIEW`，必须与确定性证据或后续动态证据联合升级。

大模型的价值主要在：跨文件理解、诱导性安装说明、描述—行为不一致和隐含意图；它不应替代密钥、权限、持久化和数据流等可确定检测。

### P2：规则校准与策略分离

- `FILE_MAGIC_MISMATCH` 应作为完整性/格式复核，不能脱离文件用途直接等价为恶意；
- GitHub/Stripe key 规则需要占位符、测试夹具、熵值和安全工具语境；
- `MANIFEST_DESCRIPTION_TOO_LONG`、`MANIFEST_MISSING_LICENSE` 属于治理或元数据质量，单独命中时不应推动恶意判定；
- `case_01928` 暂不强行写静态规则，后续用无害 fixture 验证权限和上下文访问事件。

## 6. 哪些 Skill 先补强

### 6.1 第一批新增静态规则：39 条

`case_05674`、`case_05552`、`case_05598`、`case_05683`、`case_05626`、`case_05639`、`case_05542`、`case_05520`、`case_05699`、`case_05715`、`case_03611`、`case_03247`、`case_00483`、`case_03936`、`case_03153`、`case_02205`、`case_04097`、`case_03057`、`case_01093`、`case_03637`、`case_00369`、`case_00546`、`case_01301`、`case_01905`、`case_02807`、`case_05115`、`case_03002`、`case_00287`、`case_02908`、`case_02752`、`case_02444`、`case_03573`、`case_05013`、`case_00186`、`case_05388`、`case_02743`、`case_00277`、`case_00945`、`case_03906`。

### 6.2 第一批证据关联：41 条

其中 11 条是漏报：`case_05630`、`case_05653`、`case_05611`、`case_05644`、`case_05695`、`case_05729`、`case_05737`、`case_02022`、`case_01149`、`case_03640`、`case_02789`。其余 30 条是网络、文件或命令上下文正常误报，用于验证误报抑制不能伤害攻击链检测。

### 6.3 第一批规则校准与策略分离：10 条

`case_00848`、`case_01090`、`case_05499`、`case_01789`、`case_03944`、`case_00087`、`case_01686`、`case_02548`、`case_04712`、`case_01152`。

## 7. 下一轮实现顺序

按每天 2—3 小时的资源约束，建议分四步：

1. 先实现持久化和下载—解码—执行两个规则包，并只在对应开发样本与 20 条对照上测试；
2. 实现能力声明提取与敏感源—危险汇点关联，处理 30 条网络/文件/命令误报；
3. 对 9 条候选运行一次结构化大模型语义复核，保存模型、提示词、输入哈希和 JSON 结果；
4. 规则冻结后，一次性运行 600 条回归集，输出 Cisco 基线与 Aegis 增量的配对指标；若效果不达标，回到开发集修复，但不查看回归样本正文。

回归验收必须同时报告 recall、FPR 和 abstention，不能只报告检出增加。建议的工程门槛是：开发集非正常漏报明显下降，同时 20 条正确对照不退化；回归集上正常 FPR 不允许因新增规则失控。

## 8. 证据文件

| 文件 | 作用 |
|---|---|
| `tools/evaluation/freeze_skilltrustbench_development.py` | 冻结全量结果并确定性生成开发/回归集 |
| `tools/evaluation/analyze_skilltrustbench_development.py` | 只读文本特征提取与缺口路由 |
| `baseline/skilltrustbench_v1_0/full_cisco_static_v1/` | 全量冻结基线 |
| `artifacts/analysis/2026-08-15-skilltrustbench-dev120-regression600-v1/development_cases.jsonl` | 120 条开发清单 |
| `artifacts/analysis/2026-08-15-skilltrustbench-dev120-regression600-v1/regression_cases.jsonl` | 600 条封存回归清单 |
| `artifacts/analysis/2026-08-15-skilltrustbench-dev120-regression600-v1/development_feature_analysis.jsonl` | 逐 Skill 脱敏特征与建议路线 |
| `artifacts/analysis/2026-08-15-skilltrustbench-dev120-regression600-v1/gap_summary.json` | 机器可读汇总 |
| `artifacts/analysis/2026-08-15-skilltrustbench-dev120-regression600-v1/analysis_manifest.json` | 输入输出哈希与安全证明 |

本轮新增测试后，后端测试为 `78 passed`。

## 9. 数据集分类依据

风险标签含义以 SkillTrustBench 固定数据版本和官方分类为准：T05 是越权访问与提权，T06 是系统持久化，T09 是不安全编码；T07/T08 才是工具劫持与不安全依赖。来源：[SkillTrustBench 官方数据集说明](https://matrix.tencent.com/skilltrustbench/dataset)、[Hugging Face 数据仓库 README](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench/blob/main/README.md)。
