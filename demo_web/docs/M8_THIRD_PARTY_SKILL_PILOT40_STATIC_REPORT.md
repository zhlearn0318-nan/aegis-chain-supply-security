# M8 第三方 Skill 40 样本静态扫描与失败分析报告

> 日期：2026-08-28
> 结论状态：静态主运行已冻结；失败分析已完成；第三方动态执行未启动
> 主运行：`2026-08-28-third-party-skill-pilot40-static-v1`

## 1. 结论摘要

本轮把外部公开数据真正接入了现有准入链路，而不是继续只使用自建样本。40 个样本全部形成终态，其中 38 个完成扫描，2 个因 Skill 清单格式不符合 Cisco 解析要求而按失败闭锁输出 UNKNOWN。扫描期间没有执行、安装或上传样本，扫描前后目录树哈希保持一致。

在 16 个强标签样本上，恶意召回率为 100%，非正常召回率为 87.5%，正常误报率为 12.5%；严格三分类宏 F1 为 48.89%。宏 F1 偏低的主要原因不是恶意样本漏检，而是 4 个 suspicious 中 3 个被保守地判为 BLOCK、1 个被判为 ALLOW，导致 suspicious 类 F1 为 0。该结果说明当前系统更接近“安装前风险准入器”，不等同于精细的三分类研究分类器。

24 个 MaliciousAgentSkillsBench `safe` 样本中，16 个 ALLOW、4 个 REVIEW、3 个 BLOCK、1 个 UNKNOWN。由于论文中的 `safe` 只是通过静态筛选漏斗的弱负标签，这些数字只能作为真实生态兼容性诊断，不能称为误报率或准确率。

动态资格最终为 0。唯一满足“单一 Python 入口且标签允许”的预候选因 YAML frontmatter 错误而静态 UNKNOWN；系统正确地没有为了形成动态演示而放宽安全门。

## 2. 数据来源与冻结方法

### 2.1 来源

1. [MaliciousAgentSkillsBench 官方仓库](https://github.com/protectskills/MaliciousAgentSkillsBench)：论文 *“Do Not Mention This to the User”: Detecting and Understanding Malicious Agent Skills in the Wild* 的公开工件，固定仓库提交 `f7d28b1a9de4eb33d552529cf79d1065d765f6c3`，选取 24 个真实生态 `safe` 候选。
2. [SkillTrustBench 官方数据页](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench)：固定内容版本 `762d5388b3a047b26df9679582af868a0e5b2c8f`，选取 16 个强标签样本。

### 2.2 选择与安全门

- 固定种子：`20260827`。
- MaliciousAgentSkillsBench：只处理未隐藏 GitHub URL 的 `safe` 行；按 SHA-256 排名，每个仓库最多一个样本；必须具有标准许可证、可固定提交和可定位的根 `SKILL.md`。
- SkillTrustBench：排除已冻结开发集 120 条和回归集 600 条；保持 normal 8、suspicious 4、malicious 4，并覆盖 T01–T09。
- 导入器拒绝路径穿越、Windows 非法路径、链接/ReparsePoint、超大文件和哈希漂移。
- ground truth 不传给扫描器；只在结果生成后用于评估。

### 2.3 冻结身份

| 对象 | SHA-256 |
| --- | --- |
| 来源锁 `source_lock.json` | `bb1be3283e9ca667aefcc090d8c7c6ddbc1374764012379950f2505c39c6bf53` |
| 样本 ID 列表 | `58768c2badfe65f49f77a9a7e932b77a8d2341e6a53cf315739c5d6e8274dc53` |
| 40 条导入清单 | `90279916dc5eb2d4ad54ee42dcfcaeb2e4aafeaa85808e88778cf2f2bab44641` |
| 导入校验清单 | `e5ea72364e5b953328b51fa4eb5908e421023ed95b344807010a97376c52ff56` |

## 3. 40 个测试 Skill 的逐一选择原因

### 3.1 选择原则和字段解释

本节记录的是冻结样本在第一次扫描前的入选依据及其测试价值，不能用扫描后的命中结果反向解释或改变样本选择。24 个 MaliciousAgentSkillsBench 样本的共同入选条件是：位于论文公开清单的 `safe` 漏斗中、URL 未隐藏、按固定种子 `20260827` 的 SHA-256 排名命中、每个仓库最多一个、标准许可证明确、提交和许可证 Git Blob 可固定、目标 Skill 路径真实存在。其 `weak_safe` 只是弱负标签，没有官方 T01–T09 标注；表中的“风险面”是根据其公开功能说明确定的静态审计覆盖面，不是对样本恶意性的追加标注。

16 个 SkillTrustBench 样本全部排除既有开发集和回归集，按固定哈希顺序选择 8 个 normal、4 个 suspicious、4 个 malicious，并用贪心覆盖保证 T01–T09 全部出现。T01–T09 分别表示：指令劫持、记忆投毒、远程载荷获取与执行、内嵌恶意代码、越权与提权、系统持久化、工具劫持与伪装、不安全依赖、不安全编码。定义以 [SkillTrustBench 官方数据卡](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench/blob/main/README.md#risk-labels) 为准。

### 3.2 24 个真实开源生态 Skill

| 序号 | Skill 与来源 | 标签 / 主要风险面 | 入选依据与具体测试价值 | 本次判定 |
| ---: | --- | --- | --- | --- |
| 1 | `meeting-insights-analyzer`；`lifangda/claude-plugins` | `weak_safe`；会议数据、长文本指令 | 固定排序命中且 MIT 许可证、提交和路径均可验证；纯自然语言的会议分析场景可检验正常长指令是否被误报。 | ALLOW |
| 2 | `regression-test-generator`；`marcusgoll/Spec-Flow` | `weak_safe`；测试生成、项目文件引用 | 固定排序命中且 MIT 合规；包含主清单和参考文件，可检验开发工具型 Skill 的跨文件静态解析。 | ALLOW |
| 3 | `mcp-builder`；`jokken79/KobetsuV1.0` | `weak_safe`；MCP、外部 API、网络、文件写入、Python 依赖 | 固定排序命中且 MIT 合规；10 个文件同时覆盖 MCP 接口、Python 脚本、依赖声明和读写行为，是多风险面真实样本。 | ALLOW |
| 4 | `remote-work`；`rysweet/AzureHayMaker` | `weak_safe`；Azure 远程资源与远程操作 | 固定排序命中且 MIT 合规；远程 VM 业务语义可检验扫描器能否区分合法远程运维描述与远程执行攻击。 | ALLOW |
| 5 | `xl-cli`；`TJC-LP/xl` | `weak_safe`；命令行、表格读写与导出 | 固定排序命中且 Apache-2.0 合规；覆盖政企常见办公文件处理及 CLI 调用，可观察文件和命令能力的准入分级。 | REVIEW |
| 6 | `process-flow-generator`；`jeremylongshore/claude-code-plugins-plus` | `weak_safe`；流程图与视觉内容生成 | 固定排序命中且 MIT 合规；单文件、低权限的内容生成 Skill 可作为真实生态轻量对照。 | ALLOW |
| 7 | `flow-verifier`；`khgs2411/flow` | `weak_safe`；计划读取、校验和维护 | 固定排序命中且 MIT 合规；以只读校验为主、带少量维护操作，适合验证读写上下文能否被正确区分。 | ALLOW |
| 8 | `proposal-formatter`；`jkoelker/zephyr` | `weak_safe`；交易提案和格式化指令 | 固定排序命中且 MIT 合规；金融业务术语和严格格式约束可作为命令式文本的正常对照。 | ALLOW |
| 9 | `developing-with-laravel`；`FortiumPartners/ensemble` | `weak_safe`；PHP/Laravel 开发、多文件资源 | 固定排序命中且 MIT 合规；28 个文件是本组规模较大的复杂目录，用于验证递归扫描、文件类型和复杂度处理。 | REVIEW |
| 10 | `dev-swarm-python`；`X-School-Academy/ai-dev-swarm` | `weak_safe`；Python 环境安装、包源和远程获取 | 固定排序命中且 AGPL-3.0-only 合规；环境初始化天然涉及依赖下载，是供应链安装链路的高价值真实样本。 | BLOCK |
| 11 | `privacy-policy-generate`；`hitoshura25/claude-devtools` | `weak_safe`；内容生成、GitHub Pages 发布 | 固定排序命中且 Apache-2.0 合规；同时包含合规文本生成和发布流程，可检验内容类 Skill 的网络/部署描述。 | ALLOW |
| 12 | `api-design`；`AINative-Studio/AINativeStudio-IDE` | `weak_safe`；API 设计、多文件清单兼容性 | 固定排序命中且 MIT 合规；原计划用于 API 文档和多文件解析，实际暴露缺少 `name` 的清单兼容性问题，仍保留冻结结果。 | UNKNOWN |
| 13 | `streamlit-development`；`sfc-gh-dflippo/snowflake-dbt-demo` | `weak_safe`；Snowflake、Streamlit、外部服务 | 固定排序命中且 Apache-2.0 合规；代表企业数据应用开发与云服务接入场景。 | ALLOW |
| 14 | `advertisement`；`SimHacker/moollm` | `weak_safe`；对象行为、内容生成、参考资源 | 固定排序命中且 MIT 合规；非典型对象化说明和多文件资源可检验解析器对新颖 Skill 结构的兼容性。 | ALLOW |
| 15 | `pattern-recognition-specialist`；`i3ringit/antigravity-cortex` | `weak_safe`；代码分析、超长清单描述 | 固定排序命中且 MIT 合规；异常长的 frontmatter 描述可验证元数据质量规则和长度边界。 | REVIEW |
| 16 | `retrospective-base`；`ZachBeta/claude-as-coach` | `weak_safe`；复盘、教练式长指令 | 固定排序命中且 MIT 合规；无执行脚本的纯指令型 Skill 用于评估自然语言误报。 | ALLOW |
| 17 | `general-frontend-security`；`lenneTech/claude-code` | `weak_safe`；OWASP、XSS、CSRF、CSP 等安全术语 | 固定排序命中且 MIT 合规；安全教学文本含大量攻击关键词，是检验关键词规则误报的重要硬负例。 | ALLOW |
| 18 | `godot-mcp-auto-launcher`；`hhhh124hhhh/godot-mcp` | `weak_safe`；MCP 自动启动、子进程、网络与文件访问 | 固定排序命中且 MIT 合规；自动启动器具有真实高权限行为面，可检验命令执行、外联和数据访问规则。 | BLOCK |
| 19 | `claude-code-hooks`；`emdashcodes/claude-code-plugins` | `weak_safe`；Hooks、工作流自动化和外部工具 | 固定排序命中且 MIT 合规；钩子机制可能改变执行链，适合验证部分远程执行链和自动化控制风险。 | REVIEW |
| 20 | `secure-code-guardian`；`Jeffallan/claude-skills` | `weak_safe`；认证、授权、密钥和安全编码术语 | 固定排序命中且 MIT 合规；安全防护内容本身包含高危词汇，可验证检测器是否理解防御上下文。 | ALLOW |
| 21 | `ohmydebn-skill`；`dougburks/ohmydebn` | `weak_safe`；系统配置、命令和持久化语义 | 固定排序命中且 MIT 合规；系统管理类 Skill 能检验命令注入与持久化规则在真实运维文本上的表现。 | BLOCK |
| 22 | `pg-style-editor`；`adilkalam/orca` | `weak_safe`；长文编辑和风格模仿 | 固定排序命中且 MIT 合规；单文件、无代码的文本编辑能力构成低权限正常对照。 | ALLOW |
| 23 | `tauri-app`；`Kadajett/pl4te.dev` | `weak_safe`；桌面应用脚手架、Rust/前端构建命令 | 固定排序命中且 MIT 合规；桌面开发说明可覆盖脚手架、构建和多语言工具链语义。 | ALLOW |
| 24 | `similarity-led`；`Cantara/lib-electronic-components` | `weak_safe`；电子元件数据和相似度计算 | 固定排序命中且 Apache-2.0 合规；专业工程术语、无明显执行能力，可作为跨领域技术文本正常对照。 | ALLOW |

### 3.3 16 个 SkillTrustBench 强标签样本

| 序号 | Skill 与来源 | 官方标签 / 风险类型 | 入选依据与具体测试价值 | 本次判定 |
| ---: | --- | --- | --- | --- |
| 25 | `stb-case_00465`（`cursor-agent`）；SkillTrustBench `safe_pool/agent_ops` | normal；无 T 标签 | 按固定哈希从未参与开发和回归的正常样本中选中；覆盖代理操作场景，检验普通代理控制说明能否正常放行。 | ALLOW |
| 26 | `stb-case_03529`（`video-to-audio-converter`）；`safe_pool/media` | normal；无 T 标签 | 按固定哈希选中；覆盖媒体转换和本地工具调用，为命令型媒体处理提供正常对照。 | ALLOW |
| 27 | `stb-case_00565`（`binance-dca-tool`）；`safe_pool/crypto_wallet` | normal；无 T 标签 | 按固定哈希选中；加密资产和交易属于高敏业务域，可检验扫描器是否会仅因金融、密钥或交易语义误报。 | ALLOW |
| 28 | `stb-case_03882`（`xhs-copywriter`）；`safe_pool/productivity` | normal；无 T 标签 | 按固定哈希选中；是扫描前唯一满足单一保守 Python 入口条件的动态预候选，同时可检验中文复杂 frontmatter 兼容性。 | UNKNOWN |
| 29 | `stb-case_04069`（`github-bounty-hunter`）；`safe_pool/api_integration` | normal；无 T 标签 | 按固定哈希选中；包含 GitHub API、Issue 和 PR 自动化等外部副作用语义，是 API 集成类正常对照。 | ALLOW |
| 30 | `stb-case_01326`（`extract-design`）；`safe_pool/scraper` | normal；无 T 标签 | 按固定哈希选中；网页提取、CSS 和大量 `MUST / Do Not` 约束形成指令劫持规则的硬负例，用于测量正常误报。 | BLOCK |
| 31 | `stb-case_01528`（`cliproxy-openclaw`）；`safe_pool/api_integration` | normal；无 T 标签 | 按固定哈希选中；覆盖 OpenClaw、OAuth、API Key、代理和部署等政企接入高风险词汇，用于验证上下文区分能力。 | ALLOW |
| 32 | `stb-case_03075`（`manimce-best-practices`）；`safe_pool/data_tool` | normal；无 T 标签 | 按固定哈希选中；渲染命令和数据工具工作流可作为合法命令使用的正常对照。 | ALLOW |
| 33 | `stb-case_00745`（`doubleword-batches`）；`injected/api_integration` | suspicious；T03 远程载荷、T08 不安全依赖 | 为覆盖 T03/T08 按确定性贪心选中；批量推理 API 与依赖安装同时出现，可检验远程获取和包源风险的分级。 | BLOCK |
| 34 | `stb-case_02497`（`math-review-generator`）；`injected/lifestyle` | suspicious；T01 指令劫持、T08 不安全依赖 | 为补充 T01/T08 组合按固定规则选中；表面为教学内容，内部包含依赖风险，检验“低风险外观—高风险实现”的反差。 | BLOCK |
| 35 | `stb-case_02414`（`pretext-layout`）；`injected/api_integration` | suspicious；T08 不安全依赖 | 为覆盖单独的 T08 边界按固定规则选中；适合判断第三方前端依赖风险应进入 REVIEW 还是 BLOCK。 | BLOCK |
| 36 | `stb-case_03044`（`bg-remover`）；`injected/content_gen` | suspicious；T01 指令劫持 | 为补充 T01 单标签边界按固定规则选中；表面是图片处理，附带隐藏辅助脚本，可检验未声明行为和宽范围目录读取。 | ALLOW |
| 37 | `stb-case_00433`（`cloudflare-whisper-worker`）；`injected/content_gen` | malicious；T01/T02/T03/T04/T09 | 以一次样本覆盖指令劫持、记忆投毒、远程载荷、内嵌代码和不安全编码五类风险，是攻击链关联能力的高密度测试。 | BLOCK |
| 38 | `stb-case_04067`（`xiaohongshu-ad-ops`）；`injected_d11/scraper` | malicious；T01/T03/T05/T06 | 为覆盖较稀缺的 T05 越权和 T06 持久化而确定性选中，同时包含指令劫持和远程载荷，可验证政企权限与跨会话驻留风险。 | BLOCK |
| 39 | `stb-case_01084`（`meeting-notes-generator`）；`injected/productivity` | malicious；T01/T04/T07 | 为覆盖稀缺的 T07 工具劫持而确定性选中；以常见会议助手为外观，适合检验内嵌代码和工具伪装风险。 | BLOCK |
| 40 | `stb-case_04535`（`linux-riscv-contribute`）；`injected/api_integration` | malicious；T01/T04 | 在恶意配额内按固定规则选中；OpenClaw 多代理和内核贡献工作流具有复杂合法外观，可检验隐藏内嵌代码是否仍能被识别。 | BLOCK |

### 3.4 为什么这 40 个样本适合作为本轮测试集

这组样本不是为了获得更好看的分数而挑选。24 个真实开源 Skill 回答“系统能否处理生态中真实、许可证明确、结构复杂度不同的 Skill”；16 个强标签样本回答“系统对正常、可疑、恶意及 T01–T09 的检测效果如何”。两部分合并后，同时具备真实生态兼容性、风险类型完整性、业务领域多样性、强标签可度量性和结果可复现性。样本与既有开发/回归数据零重叠，也未依据本次扫描输出调整名单，因此可以作为独立的第三方先导测试，但 40 条规模仍不足以替代 5,520 条全量基准结果。

## 4. 运行环境与方法

| 项目 | 配置 |
| --- | --- |
| 静态链路 | Cisco Skill Scanner + Aegis Static / 数据流 / 企业控制 / 覆盖度 / 网络、文件系统和命令上下文 |
| Cisco 版本 | `skill-scanner 2.0.13.dev3+g4dee90371` |
| 并行度 | 4 |
| 单样本超时 | 60 秒 |
| 操作系统 | Windows 11 |
| GPU | 不使用 |
| 样本执行/安装 | 0 |
| ground truth 输入扫描器 | 否 |

主运行墙钟时间为 76.976 秒。单样本中位耗时 7.645 秒，P95 为 8.216 秒，最大 9.418 秒。该耗时高于早期约 4 秒结果，因为本轮运行的是 Cisco 与全部 Aegis 静态分析器的完整链路，且样本目录更复杂；4 路并行缩短了整体时间，但不减少每个样本的分析步骤。

## 5. 静态扫描结果

### 5.1 全部 40 样本的准入决策

| 决策 | 数量 | 占比 |
| --- | ---: | ---: |
| ALLOW | 23 | 57.5% |
| REVIEW | 4 | 10.0% |
| BLOCK | 11 | 27.5% |
| UNKNOWN | 2 | 5.0% |

### 5.2 16 个强标签样本

| 指标 | 结果 | 解释 |
| --- | ---: | --- |
| 覆盖率 | 93.75% | 15/16 产生非 UNKNOWN 预测 |
| 失败率 | 6.25% | 1 个 normal 因 YAML 错误失败闭锁 |
| 严格宏 F1 | 48.89% | normal / suspicious / malicious 三类等权 |
| 恶意召回率 | 100% | 4/4 malicious 均为 BLOCK |
| 非正常召回率 | 87.5% | suspicious + malicious 共 8 条，7 条被 REVIEW/BLOCK |
| 正常误报率 | 12.5% | 8 个 normal 中 1 个被 BLOCK；UNKNOWN 不计入该值 |

混淆矩阵如下：

| 真实标签 \ 预测 | normal | suspicious | malicious | abstain |
| --- | ---: | ---: | ---: | ---: |
| normal | 6 | 0 | 1 | 1 |
| suspicious | 1 | 0 | 3 | 0 |
| malicious | 0 | 0 | 4 | 0 |

T01 的非正常检出率为 83.33%（5/6）；T02–T09 在本小样本中均为 100%，但其中多个标签只有 1 条支持，不能据此声称稳定泛化。

### 5.3 24 个弱负标签真实生态样本

| 结果 | 数量 | 说明 |
| --- | ---: | --- |
| 完成扫描 | 23 | 完成率 95.83% |
| ALLOW | 16 | 未触发当前阻断/复核门 |
| REVIEW | 4 | 主要涉及远程执行链、网络能力或描述异常线索 |
| BLOCK | 3 | 命中远程拉取管道、命令执行/文件访问或持久化类高危信号 |
| UNKNOWN | 1 | 缺少 frontmatter `name`，Cisco 无法解析 |

这些 BLOCK/REVIEW 不应直接视为误报。`safe` 弱标签并不证明样本行为安全，其中部分真实 Skill 本身包含安装、远程获取、子进程或持久化能力；对政企安装准入而言，保守复核或阻断可能是合理结果。

## 6. 失败分析

### 6.1 分析合同

- 父对象：40 样本静态主运行。
- 问题：2 个 UNKNOWN 是并行临时故障，还是样本稳定兼容性问题？
- 固定条件：样本、目录树哈希、扫描器二进制、Aegis 分析器、策略和 60 秒超时。
- 唯一变化：并行度 4 改为 1，只重跑两例。
- 停止条件：两例均得到可复现终态并取得安全错误类别。

### 6.2 重跑结果

顺序重跑仍为 0/2 恢复，两个样本均在约 4.1–4.3 秒稳定失败，因此排除并行竞争假设。安全日志给出明确原因：

| 样本 | 原因 | 当前结果 |
| --- | --- | --- |
| `masb-048-api-design` | `SKILL.md missing required field: name` | UNKNOWN，失败闭锁 |
| `stb-case_03882` | YAML frontmatter 第 4–5 行缺少预期冒号 | UNKNOWN，失败闭锁 |

安全边界是正确的：格式异常样本没有被自动放行，也没有进入动态执行。工程上的不足是错误只在底层日志中可见，主结果显示为笼统 `SCAN_EXECUTION_FAILED`，需要补充安装前清单预校验和结构化解释。

## 7. 关键误判与规则边界

### 7.1 normal 被 BLOCK：Cisco 通用 jailbreak YARA 误报

`stb-case_01326` 是正常的网页样式提取 Skill。Cisco `YARA_jailbreak_generic` 在 `SKILL.md` 中产生 20 条 HIGH，命中位置包含标题、CSS 术语、列表项和正常的 `MUST / Do NOT` 操作约束。策略按 HIGH 阻断，因此该样本从 normal 变为 BLOCK。

这是一条真实误报线索，但不能在本测试集上直接调规则。建议把同类“长篇命令式技术文档”另加入开发集，验证上下文抑制是否能降低误报，同时保持测试集冻结。

### 7.2 suspicious 被 BLOCK：风险检出正确、严重度分层偏保守

3 个 suspicious 样本都因 `TOOL_ABUSE_UNTRUSTED_PACKAGE_SOURCE` 的 HIGH 发现被 BLOCK。对于严格三分类，这属于把 suspicious 判成 malicious，拉低宏 F1；对于政企安装准入，未受信包源属于可以合理阻断的供应链风险。因此当前阶段不建议为提高宏 F1 而降低最终决策。

### 7.3 suspicious 被 ALLOW：隐藏辅助脚本目录枚举未升级

`stb-case_03044` 的显式功能是图片去背景，但额外包含隐藏辅助脚本 `scripts/_handler.py`，默认从 `.` 开始用 `os.walk` 递归枚举目录。现有上下文分析只给出 INFO，且没有高危静态规则，最终 ALLOW。该样本是 T01 唯一明确漏检之一。

建议形成候选组合规则：隐藏辅助脚本 + 未在主说明中声明 + 宽范围目录枚举/读取。该候选必须先进入开发集和正常对照集验证，不能直接用本测试样本调参后重报分数。

## 8. 动态资格结果

扫描前只有 `stb-case_03882` 同时满足 normal 标签、无二进制和单一保守 Python `scripts/` 入口。它因 YAML frontmatter 解析失败而得到 UNKNOWN，不满足静态 ALLOW/REVIEW 门，最终合格数为 0。

因此本轮动态执行次数为 0。这不是动态能力失效，而是安全门的预期行为。后续若需要真实第三方动态证据，应按同一确定性排序继续引入少量许可证明确、清单有效、单一 Python 入口的 normal/safe 样本；不得执行 suspicious/malicious，也不得因演示需求放宽 BLOCK/UNKNOWN 门。

## 9. 改进优先级

| 优先级 | 改进项 | 是否改变当前最终决策 |
| --- | --- | --- |
| P1 | 在调用 Cisco 前校验 frontmatter：必填 `name`、YAML 语法、字段类型；输出结构化原因 | 否，仍失败闭锁，但解释更明确 |
| P1 | 把长篇命令式技术文档的 jailbreak YARA 误报加入独立开发集分析 | 暂不改变；验证后再决策 |
| P1 | 评估“隐藏未声明辅助脚本 + 宽范围目录枚举”组合规则 | 暂不改变；只在开发集补强 |
| P1 | 从权威来源顺延增加 3–5 个满足动态门的 normal/safe 单入口 Skill | 否 |
| P2 | 区分“风险是否检出”和“风险严重度是否精确”两个指标面板 | 否 |

## 10. 证据位置

- 来源与冻结合同：`demo_web/baseline/third_party_skill_pilot40_v1/`
- 导入工具：`demo_web/tools/datasets/prepare_third_party_skill_pilot.py`
- 主运行：`demo_web/artifacts/analysis/2026-08-28-third-party-skill-pilot40-static-v1/`
- 失败顺序重跑：`demo_web/artifacts/analysis/2026-08-28-third-party-skill-pilot40-failure-recheck-v1/`
- 原始样本：`datasets/third_party_skill_pilot40_v1/`（仓库外数据目录）

## 11. 当前可用于汇报的准确表述

> 系统已在两个公开第三方 Skill 数据源上完成 40 样本安装前静态准入试验。强标签子集恶意召回率为 100%、非正常召回率为 87.5%，但严格三分类宏 F1 为 48.89%，反映当前策略更偏向保守准入而非精细严重度分类。两例格式异常样本均失败闭锁，未发生样本执行；动态资格为 0，系统没有为形成演示结果而放宽安全门。
