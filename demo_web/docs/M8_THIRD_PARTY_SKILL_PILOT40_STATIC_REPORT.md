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

## 3. 运行环境与方法

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

## 4. 静态扫描结果

### 4.1 全部 40 样本的准入决策

| 决策 | 数量 | 占比 |
| --- | ---: | ---: |
| ALLOW | 23 | 57.5% |
| REVIEW | 4 | 10.0% |
| BLOCK | 11 | 27.5% |
| UNKNOWN | 2 | 5.0% |

### 4.2 16 个强标签样本

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

### 4.3 24 个弱负标签真实生态样本

| 结果 | 数量 | 说明 |
| --- | ---: | --- |
| 完成扫描 | 23 | 完成率 95.83% |
| ALLOW | 16 | 未触发当前阻断/复核门 |
| REVIEW | 4 | 主要涉及远程执行链、网络能力或描述异常线索 |
| BLOCK | 3 | 命中远程拉取管道、命令执行/文件访问或持久化类高危信号 |
| UNKNOWN | 1 | 缺少 frontmatter `name`，Cisco 无法解析 |

这些 BLOCK/REVIEW 不应直接视为误报。`safe` 弱标签并不证明样本行为安全，其中部分真实 Skill 本身包含安装、远程获取、子进程或持久化能力；对政企安装准入而言，保守复核或阻断可能是合理结果。

## 5. 失败分析

### 5.1 分析合同

- 父对象：40 样本静态主运行。
- 问题：2 个 UNKNOWN 是并行临时故障，还是样本稳定兼容性问题？
- 固定条件：样本、目录树哈希、扫描器二进制、Aegis 分析器、策略和 60 秒超时。
- 唯一变化：并行度 4 改为 1，只重跑两例。
- 停止条件：两例均得到可复现终态并取得安全错误类别。

### 5.2 重跑结果

顺序重跑仍为 0/2 恢复，两个样本均在约 4.1–4.3 秒稳定失败，因此排除并行竞争假设。安全日志给出明确原因：

| 样本 | 原因 | 当前结果 |
| --- | --- | --- |
| `masb-048-api-design` | `SKILL.md missing required field: name` | UNKNOWN，失败闭锁 |
| `stb-case_03882` | YAML frontmatter 第 4–5 行缺少预期冒号 | UNKNOWN，失败闭锁 |

安全边界是正确的：格式异常样本没有被自动放行，也没有进入动态执行。工程上的不足是错误只在底层日志中可见，主结果显示为笼统 `SCAN_EXECUTION_FAILED`，需要补充安装前清单预校验和结构化解释。

## 6. 关键误判与规则边界

### 6.1 normal 被 BLOCK：Cisco 通用 jailbreak YARA 误报

`stb-case_01326` 是正常的网页样式提取 Skill。Cisco `YARA_jailbreak_generic` 在 `SKILL.md` 中产生 20 条 HIGH，命中位置包含标题、CSS 术语、列表项和正常的 `MUST / Do NOT` 操作约束。策略按 HIGH 阻断，因此该样本从 normal 变为 BLOCK。

这是一条真实误报线索，但不能在本测试集上直接调规则。建议把同类“长篇命令式技术文档”另加入开发集，验证上下文抑制是否能降低误报，同时保持测试集冻结。

### 6.2 suspicious 被 BLOCK：风险检出正确、严重度分层偏保守

3 个 suspicious 样本都因 `TOOL_ABUSE_UNTRUSTED_PACKAGE_SOURCE` 的 HIGH 发现被 BLOCK。对于严格三分类，这属于把 suspicious 判成 malicious，拉低宏 F1；对于政企安装准入，未受信包源属于可以合理阻断的供应链风险。因此当前阶段不建议为提高宏 F1 而降低最终决策。

### 6.3 suspicious 被 ALLOW：隐藏辅助脚本目录枚举未升级

`stb-case_03044` 的显式功能是图片去背景，但额外包含隐藏辅助脚本 `scripts/_handler.py`，默认从 `.` 开始用 `os.walk` 递归枚举目录。现有上下文分析只给出 INFO，且没有高危静态规则，最终 ALLOW。该样本是 T01 唯一明确漏检之一。

建议形成候选组合规则：隐藏辅助脚本 + 未在主说明中声明 + 宽范围目录枚举/读取。该候选必须先进入开发集和正常对照集验证，不能直接用本测试样本调参后重报分数。

## 7. 动态资格结果

扫描前只有 `stb-case_03882` 同时满足 normal 标签、无二进制和单一保守 Python `scripts/` 入口。它因 YAML frontmatter 解析失败而得到 UNKNOWN，不满足静态 ALLOW/REVIEW 门，最终合格数为 0。

因此本轮动态执行次数为 0。这不是动态能力失效，而是安全门的预期行为。后续若需要真实第三方动态证据，应按同一确定性排序继续引入少量许可证明确、清单有效、单一 Python 入口的 normal/safe 样本；不得执行 suspicious/malicious，也不得因演示需求放宽 BLOCK/UNKNOWN 门。

## 8. 改进优先级

| 优先级 | 改进项 | 是否改变当前最终决策 |
| --- | --- | --- |
| P1 | 在调用 Cisco 前校验 frontmatter：必填 `name`、YAML 语法、字段类型；输出结构化原因 | 否，仍失败闭锁，但解释更明确 |
| P1 | 把长篇命令式技术文档的 jailbreak YARA 误报加入独立开发集分析 | 暂不改变；验证后再决策 |
| P1 | 评估“隐藏未声明辅助脚本 + 宽范围目录枚举”组合规则 | 暂不改变；只在开发集补强 |
| P1 | 从权威来源顺延增加 3–5 个满足动态门的 normal/safe 单入口 Skill | 否 |
| P2 | 区分“风险是否检出”和“风险严重度是否精确”两个指标面板 | 否 |

## 9. 证据位置

- 来源与冻结合同：`demo_web/baseline/third_party_skill_pilot40_v1/`
- 导入工具：`demo_web/tools/datasets/prepare_third_party_skill_pilot.py`
- 主运行：`demo_web/artifacts/analysis/2026-08-28-third-party-skill-pilot40-static-v1/`
- 失败顺序重跑：`demo_web/artifacts/analysis/2026-08-28-third-party-skill-pilot40-failure-recheck-v1/`
- 原始样本：`datasets/third_party_skill_pilot40_v1/`（仓库外数据目录）

## 10. 当前可用于汇报的准确表述

> 系统已在两个公开第三方 Skill 数据源上完成 40 样本安装前静态准入试验。强标签子集恶意召回率为 100%、非正常召回率为 87.5%，但严格三分类宏 F1 为 48.89%，反映当前策略更偏向保守准入而非精细严重度分类。两例格式异常样本均失败闭锁，未发生样本执行；动态资格为 0，系统没有为形成演示结果而放宽安全门。
