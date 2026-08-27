# M8 第三方 Skill 权威数据集选型与首轮试验合同

> 日期：2026-08-27
> 状态：已完成选型、固定基线和首轮静态扫描；结果见 `M8_THIRD_PARTY_SKILL_PILOT40_STATIC_REPORT.md`

## 1. 任务边界

目标不是再制作自建攻击样本，而是从论文或论文作者公开的数据集中固定 30–50 个第三方 Skill，检验现有静态准入和 Docker 动态审计面对外部样本时的兼容性与真实性。

安全边界：全部样本先静态扫描；动态试运行只允许“数据集标签为 safe/normal、静态结果为 ALLOW 或 REVIEW、纯 Python 脚本、无链接和原生二进制”的样本。已知 vulnerable/malicious、静态 BLOCK/UNKNOWN、许可证不清或入口不明确的样本只做静态审查，禁止执行。样本不足时减少动态数量，不降低安全门。

## 2. 权威候选核验

### 2.1 MaliciousAgentSkillsBench（主来源）

- 论文：Yi Liu 等，*“Do Not Mention This to the User”: Detecting and Understanding Malicious Agent Skills in the Wild*，arXiv:2602.06547，USENIX Security 2026。
- 官方仓库：[protectskills/MaliciousAgentSkillsBench](https://github.com/protectskills/MaliciousAgentSkillsBench)
- 永久归档：[Zenodo 10.5281/zenodo.20285751](https://doi.org/10.5281/zenodo.20285751)
- 许可：MIT。
- 权威性：官方仓库声明通过 USENIX Security 2026 Artifact Evaluation，并获得 Artifacts Available、Artifacts Functional、Results Reproduced 徽章。
- 数据规模：98,380 个 Skill 的生态快照，4,287 个静态可疑候选，其中 157 个经行为确认的恶意 Skill、632 个漏洞实例。
- 重要限制：公开表中恶意仓库 URL 被主动隐藏，避免传播真实恶意代码；`safe` 是该论文漏斗中的未命中静态候选，不等于经过逐个行为验证的绝对安全。

决策：首轮从 `skills_dataset.csv` 的 `safe` 行中确定性抽取 24 个可下载候选；逐仓库检查许可证、固定提交、目录和文件哈希。它们全部先静态扫描，只有同时通过外部标签和本系统动态资格门的纯 Python Skill 才能进入断网 Docker。157 个恶意样本只使用公开元数据做标签/攻击类型对照，不尝试还原被隐藏的下载地址。

### 2.2 SkillTrustBench v1.0（补充来源）

- 官方数据页：[cuhk-zhuque/SkillTrustBench](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench)
- 工业实验室页面：[Tencent Zhuque Lab SkillTrustBench](https://matrix.tencent.com/skilltrustbench/)
- 许可：CC BY-NC-SA 4.0。
- 数据规模：5,520 个 agent-skill 风格案例，包含 `normal / vulnerable / malicious` 标签以及九类攻击切片；提供 `SKILL.md` 与可选脚本、参考资料和资产。
- 当前关系：本项目已经完成该数据集的静态全量扫描并冻结结果，但尚未把外部 normal Skill 作为第三方动态沙箱样本执行。

决策：从已冻结数据中另取 16 个与开发集/回归集目的不同的第三方动态试点样本：8 normal、4 vulnerable、4 malicious。三类全部重新走当前静态准入；vulnerable/malicious 永不执行，normal 仍须满足静态 ALLOW/REVIEW、Python 入口和文件安全门才能动态运行。

### 2.3 暂不进入首轮的候选

| 数据集 | 暂缓原因 |
| --- | --- |
| GitSkills（arXiv:2608.10906） | 3,797,117 个 GitHub `SKILL.md`，适合生态研究，但没有安全真值；还需逐仓库许可证核验，不能直接作为首轮安全检出评测。 |
| HarmfulSkillBench（arXiv:2604.15415） | MIT、200 个有害/高风险 Skill，但数据集受 Hugging Face gate 管理，且大量样本是自然语言能力描述，主要评测 LLM 拒绝而非脚本动态审计。 |
| AgentJailbreak（arXiv:2608.05223） | 2,826 个基于真实 Shell 命令生成的对抗 Skill，仓库提示仅限隔离环境，但首轮未找到清晰标准许可证；不满足本轮许可证门。 |
| MalSkillBench（arXiv:2606.07131） | 3,944 恶意、4,000 良性完整包，相关性高，但当前仅声明“academic research use only”而非标准开源许可证，且一次性引入大规模恶意包不符合小规模安全试验原则。 |

## 3. 首轮 40 样本合同

| 来源 | 标签构成 | 数量 | 是否可能动态执行 |
| --- | --- | ---: | --- |
| MaliciousAgentSkillsBench | `safe` 候选 | 24 | 仅限逐仓库许可通过、固定提交、静态 ALLOW/REVIEW、纯 Python 且无链接/二进制者 |
| SkillTrustBench v1.0 | normal 8 / vulnerable 4 / malicious 4 | 16 | 仅 normal 且通过全部资格门者 |
| 合计 | 外部真实生态 + 构造标签基准 | 40 | 数量由安全门决定，不设最低执行数来倒逼放宽策略 |

选择固定种子 `20260827`，按来源、标签和样本 ID 排序后确定性抽样。扫描器运行时不读取 ground truth；标签只在结果生成后用于评测。动态资格门单独读取标签，是为了明确禁止执行已知 vulnerable/malicious 样本。

## 4. 评价合同

### 静态阶段

- 40/40 形成 completed 或 failed/UNKNOWN 终态；
- 记录 ALLOW/REVIEW/BLOCK/UNKNOWN 分布、按来源/标签的混淆情况、规则覆盖和 abstain；
- 扫描前后目录树哈希一致；
- 不因本轮结果调整已冻结的静态最终决策规则。

### 动态资格阶段

- 外部标签必须为 safe/normal；
- 静态决策必须是 ALLOW 或 REVIEW；
- 只接受有界发现的 Python 入口；
- 拒绝软链接/ReparsePoint、原生二进制、超限目录、未知入口和哈希变化；
- 资格清单及每个文件 SHA-256 固化后才允许执行。

### 动态阶段

- 首轮每个合格样本执行 1 次；若全部遥测、容器安全门和清理门通过，再对合格集追加 2 轮稳定性复核；
- 记录动态 ALLOW/REVIEW/BLOCK、静态→动态升级、规则、时延、遥测完整性和跨轮稳定性；
- 危险结果只允许提高风险，不能降低静态决策；
- 容器残留、宿主敏感路径挂载、互联网、GPU、云服务均为 0。

## 5. 实际落地状态（2026-08-28）

- 已固定 24 个 MaliciousAgentSkillsBench 真实生态 Skill；逐仓库记录提交、Skill 路径、SPDX 许可证和许可证 Git Blob。
- 有 5 个已通过许可证门的原候选因固定提交中已找不到同名 Skill 而被拒绝，并按确定性排序顺延补位。
- 已固定 16 个不与现有开发集 120 条、回归集 600 条重叠的 SkillTrustBench 样本，保持 normal 8 / suspicious 4 / malicious 4 且覆盖 T01–T09。
- 已完成 40 条 Cisco + Aegis 全静态链路扫描；主运行不执行、不安装、不上传样本。
- 动态资格最终为 0，因此没有为了演示效果放宽安全门或执行第三方代码。

## 6. 下一锚点

下一阶段采用“输入清单解释性补强 + 追加合格动态候选”路线：先为缺失 `name`、YAML frontmatter 语法错误提供结构化准入解释，但不改变失败闭锁结果；再从同一权威来源顺延选择少量 normal/safe、单一 Python 入口且静态 ALLOW/REVIEW 的候选。只有资格报告出现合格样本后才进入真实 Docker 动态实验。
