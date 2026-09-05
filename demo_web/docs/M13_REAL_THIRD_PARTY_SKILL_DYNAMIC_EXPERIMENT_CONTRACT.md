# M13 真实第三方 Skill 容器动态审计实验契约

## 1. 实验目的

本实验回答两个问题：

1. 现有动态审计是否能让许可证清晰、人工筛查为低风险的真实第三方 Skill 脚本正常运行，而不是“几乎全部不通过”；
2. 在保留真实 Skill 完整包和原始入口的条件下加入可控风险行为后，系统能否在安装前隔离试运行中观察到对应行为并升级准入决策。

本契约在正式主实验前冻结。主实验开始后，不根据结果修改样本、规则、预期标签或验收阈值。

## 2. 数据组成

- 数据集 ID：`third-party-skill-dynamic-pairs-v1`
- 总样本：36 个 Skill 包
- 真实原始样本：6 个
- 受控风险孪生：30 个
- 运行时：Python 18 个、Node 18 个
- 来源：OpenAI 官方 Skills 仓库 5 个原型、Anthropic 官方 Skills 仓库 1 个原型
- 许可证：所选 6 个原型均为 Apache-2.0
- 固定提交：
  - OpenAI Skills：`49f948faa9258a0c61caceaf225e179651397431`
  - Anthropic Skills：`3b3fad96af16a10759d930941b4520ba0c40edae`

每个原型生成 1 个原始样本与 5 个受控风险孪生：

| 风险类型 | 预期动态规则 | 预期决策 |
|---|---|---|
| 诱饵数据访问 | `AEGIS_DYNAMIC_DECOY_ACCESS` | BLOCK |
| Shell 启动 | `AEGIS_DYNAMIC_SHELL_SPAWN` | BLOCK |
| 敏感路径访问 | `AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS` | BLOCK |
| 外部网络尝试 | `AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT` | BLOCK |
| 对抗轮超时 | `AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT` | REVIEW |

风险行为只在 `adversarial` 轮触发。孪生样本通过受控包装器先产生实验行为，再执行未修改的上游原始入口；原始入口文件哈希必须与固定仓库一致。

## 3. 为什么选择这 6 个真实 Skill

| 原型 | 发布方 | 运行时 | 选择原因 |
|---|---|---|---|
| `jupyter-notebook` | OpenAI | Python | 读取随包模板并在容器临时目录生成 Notebook，覆盖真实文件读写 |
| `plugin-creator` | OpenAI | Python | 生成多文件插件骨架，覆盖目录与配置文件写入 |
| `security-ownership-map` | OpenAI | Python | 读取无敏感合成治理数据，贴近政企代码责任分析场景 |
| `chatgpt-apps` | OpenAI | Node | 生成 MCP Apps 脚手架，覆盖 Node 多文件写入与 MCP 场景 |
| `openai-docs` | OpenAI | Node | 使用固定本地文档验证真实解析逻辑，避免真实联网 |
| `algorithmic-art` | Anthropic | Node | 无外部依赖、无顶层副作用，可作为低风险 Node 对照 |

选择不是随机代表性抽样，而是“权威来源、许可证清晰、含真实脚本、可在断网沙箱中安全完成”的目的性抽样。因此实验能够证明工程可运行性和行为检测能力，但不能估计整个开放 Skill 生态的总体风险率。

## 4. 安全边界

- 不执行任何已知恶意第三方 Skill；
- 仅执行人工筛查后的低风险真实脚本及实验受控孪生；
- Docker 网络模式固定为 `none`；
- Skill 与审计工具均只读挂载；
- 容器使用非 root 用户 `65532:65532`；
- 删除全部 Linux capabilities，启用 `no-new-privileges`；
- 限制 CPU、内存、PID、临时目录和单包总时间；
- 每次运行后必须验证容器已移除且无残留；
- 写入只允许发生在容器内 `/workspace` 或 `/tmp` 的临时内存文件系统。

## 5. 主实验流程

1. 验证数据清单、来源提交、原始入口 SHA-256 与每个样本树 SHA-256；
2. 使用 Cisco Skill Scanner + Aegis 静态规则扫描 36 个包；
3. 对每个包使用同一容器后端执行 `typical`、`edge`、`adversarial` 三轮；
4. 记录运行事件、动态规则、静态/动态决策、镜像门、容器配置门、参数哈希和清理证据；
5. 扫描后再次计算样本树 SHA-256，确认第三方包未被修改；
6. 按冻结指标和阈值自动生成验收结论及 Markdown 报告。

36 个包各执行三轮，共形成 108 次真实容器脚本调用。

## 6. 冻结指标与阈值

| 指标 | 验收阈值 |
|---|---:|
| 30 个受控风险的预期动态规则召回率 | ≥ 90% |
| 30 个受控风险的 REVIEW/BLOCK 召回率 | ≥ 90% |
| 6 个原始真实 Skill 的 ALLOW 率 | ≥ 80% |
| 三轮证明完整率 | 100% |
| 容器安全门通过率 | 100% |
| 容器清理验证率 | 100% |
| 样本树不变率 | 100% |

同时报告但不作为本轮硬阈值：静态到动态的决策增量、分风险召回率、单包耗时和基础设施成功率。

## 7. 结果解释边界

受控风险孪生证明的是系统对指定运行时行为的检测效果，不能据此声称 OpenAI 或 Anthropic 上游 Skill 自身恶意。语言级 Python/Node 钩子提供可解释证据，但仍可能被有意绕过；Docker 的断网、只读、非 root 和资源限制才是本轮执行的安全边界，不能把语言级遥测表述为内核级完整检测。
