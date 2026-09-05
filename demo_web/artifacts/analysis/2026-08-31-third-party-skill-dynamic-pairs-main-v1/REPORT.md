# 真实第三方 Skill 容器动态审计效果报告

- 主实验结论：**PASS**
- 真实来源原型：6 个（OpenAI 5 个、Anthropic 1 个），均为 Apache-2.0
- 配对样本：6 个原始样本 + 30 个受控风险孪生样本 = 36 个 Skill 包
- 实际容器脚本调用：108 次（每包 typical / edge / adversarial 三轮）
- 安全边界：已知恶意第三方 Skill 未执行；所有执行均断网、只读挂载、非 root、能力清空并限制资源

## 核心指标

| 指标 | 结果 | 含义 |
|---|---:|---|
| 受控风险预期规则召回率 | 100.0% | 30 个风险孪生中，动态审计是否抓到对应行为规则 |
| 受控风险非放行召回率 | 100.0% | 风险孪生是否至少进入 REVIEW/BLOCK |
| 原始真实 Skill 放行率 | 100.0% | 正常真实脚本是否未被动态审计误伤 |
| adversarial 轮触发证明 | 100.0% | 风险事件是否确实只在对抗轮被观察 |
| 三轮证明完整率 | 100.0% | 每个包是否完成三类输入证明 |
| 容器安全门通过率 | 100.0% | 镜像、断网、只读、非 root 等门是否全部成立 |
| 容器清理通过率 | 100.0% | 每次运行后是否验证无残留 |
| 样本树不变率 | 100.0% | 扫描前后第三方包哈希是否一致 |
| 动态决策增量 | 18/36 | 动态证据使最终决策比静态更严格的样本数 |
| 单包动态耗时 | 中位 5002 ms，均值 4387 ms，最大 10290 ms | 含三轮容器运行与安全门校验 |

## 分风险类型结果

| 风险类型 | 样本数 | 对应规则命中 | 非放行 | adversarial 轮事件 |
|---|---:|---:|---:|---:|
| adversarial_timeout | 6 | 6 | 6 | 6 |
| decoy_access | 6 | 6 | 6 | 6 |
| external_network | 6 | 6 | 6 | 6 |
| sensitive_path | 6 | 6 | 6 | 6 |
| shell_spawn | 6 | 6 | 6 | 6 |

## 6 个真实 Skill 的选择原因与结果

| 原型 | 发布方 | 运行时 | 选择原因 | 原始动态决策 |
|---|---|---|---|---|
| openai-jupyter-notebook | OpenAI | python | Apache-2.0；仅使用标准库读取随包模板并写入容器临时目录，可验证真实文件处理脚本。 | ALLOW |
| openai-plugin-creator | OpenAI | python | Apache-2.0；仅使用标准库生成插件骨架，输出限定在容器临时目录，可验证多文件写入。 | ALLOW |
| openai-security-ownership-map | OpenAI | python | Apache-2.0；对随包无敏感合成数据执行只读查询，可验证真实政企代码治理类脚本。 | ALLOW |
| openai-chatgpt-apps | OpenAI | node | Apache-2.0；Node 标准库生成 MCP Apps 脚手架，输出限定在容器临时目录。 | ALLOW |
| openai-openai-docs | OpenAI | node | Apache-2.0；强制读取本地固定文档而非联网，可验证真实解析逻辑与本地文件访问。 | ALLOW |
| anthropic-algorithmic-art | Anthropic | node | Apache-2.0；无外部依赖、无顶层副作用的真实生成式艺术模板，可作为 Node 低风险对照。 | ALLOW |

## 逐样本静态/动态对照

| 样本 | 类型 | 风险 | 静态 | 动态 | 预期动态规则 | 命中 |
|---|---|---|---|---|---|---|
| openai-jupyter-notebook--original | original | none | REVIEW | ALLOW | - | - |
| openai-jupyter-notebook--decoy_access | controlled_risk_twin | decoy_access | REVIEW | BLOCK | AEGIS_DYNAMIC_DECOY_ACCESS | 是 |
| openai-jupyter-notebook--shell_spawn | controlled_risk_twin | shell_spawn | REVIEW | BLOCK | AEGIS_DYNAMIC_SHELL_SPAWN | 是 |
| openai-jupyter-notebook--sensitive_path | controlled_risk_twin | sensitive_path | REVIEW | BLOCK | AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS | 是 |
| openai-jupyter-notebook--external_network | controlled_risk_twin | external_network | REVIEW | BLOCK | AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT | 是 |
| openai-jupyter-notebook--adversarial_timeout | controlled_risk_twin | adversarial_timeout | REVIEW | REVIEW | AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT | 是 |
| openai-plugin-creator--original | original | none | REVIEW | ALLOW | - | - |
| openai-plugin-creator--decoy_access | controlled_risk_twin | decoy_access | REVIEW | BLOCK | AEGIS_DYNAMIC_DECOY_ACCESS | 是 |
| openai-plugin-creator--shell_spawn | controlled_risk_twin | shell_spawn | REVIEW | BLOCK | AEGIS_DYNAMIC_SHELL_SPAWN | 是 |
| openai-plugin-creator--sensitive_path | controlled_risk_twin | sensitive_path | REVIEW | BLOCK | AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS | 是 |
| openai-plugin-creator--external_network | controlled_risk_twin | external_network | REVIEW | BLOCK | AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT | 是 |
| openai-plugin-creator--adversarial_timeout | controlled_risk_twin | adversarial_timeout | REVIEW | REVIEW | AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT | 是 |
| openai-security-ownership-map--original | original | none | BLOCK | ALLOW | - | - |
| openai-security-ownership-map--decoy_access | controlled_risk_twin | decoy_access | BLOCK | BLOCK | AEGIS_DYNAMIC_DECOY_ACCESS | 是 |
| openai-security-ownership-map--shell_spawn | controlled_risk_twin | shell_spawn | BLOCK | BLOCK | AEGIS_DYNAMIC_SHELL_SPAWN | 是 |
| openai-security-ownership-map--sensitive_path | controlled_risk_twin | sensitive_path | BLOCK | BLOCK | AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS | 是 |
| openai-security-ownership-map--external_network | controlled_risk_twin | external_network | BLOCK | BLOCK | AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT | 是 |
| openai-security-ownership-map--adversarial_timeout | controlled_risk_twin | adversarial_timeout | BLOCK | REVIEW | AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT | 是 |
| openai-chatgpt-apps--original | original | none | REVIEW | ALLOW | - | - |
| openai-chatgpt-apps--decoy_access | controlled_risk_twin | decoy_access | REVIEW | BLOCK | AEGIS_DYNAMIC_DECOY_ACCESS | 是 |
| openai-chatgpt-apps--shell_spawn | controlled_risk_twin | shell_spawn | BLOCK | BLOCK | AEGIS_DYNAMIC_SHELL_SPAWN | 是 |
| openai-chatgpt-apps--sensitive_path | controlled_risk_twin | sensitive_path | REVIEW | BLOCK | AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS | 是 |
| openai-chatgpt-apps--external_network | controlled_risk_twin | external_network | REVIEW | BLOCK | AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT | 是 |
| openai-chatgpt-apps--adversarial_timeout | controlled_risk_twin | adversarial_timeout | REVIEW | REVIEW | AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT | 是 |
| openai-openai-docs--original | original | none | REVIEW | ALLOW | - | - |
| openai-openai-docs--decoy_access | controlled_risk_twin | decoy_access | REVIEW | BLOCK | AEGIS_DYNAMIC_DECOY_ACCESS | 是 |
| openai-openai-docs--shell_spawn | controlled_risk_twin | shell_spawn | BLOCK | BLOCK | AEGIS_DYNAMIC_SHELL_SPAWN | 是 |
| openai-openai-docs--sensitive_path | controlled_risk_twin | sensitive_path | REVIEW | BLOCK | AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS | 是 |
| openai-openai-docs--external_network | controlled_risk_twin | external_network | REVIEW | BLOCK | AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT | 是 |
| openai-openai-docs--adversarial_timeout | controlled_risk_twin | adversarial_timeout | REVIEW | REVIEW | AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT | 是 |
| anthropic-algorithmic-art--original | original | none | ALLOW | ALLOW | - | - |
| anthropic-algorithmic-art--decoy_access | controlled_risk_twin | decoy_access | ALLOW | BLOCK | AEGIS_DYNAMIC_DECOY_ACCESS | 是 |
| anthropic-algorithmic-art--shell_spawn | controlled_risk_twin | shell_spawn | BLOCK | BLOCK | AEGIS_DYNAMIC_SHELL_SPAWN | 是 |
| anthropic-algorithmic-art--sensitive_path | controlled_risk_twin | sensitive_path | ALLOW | BLOCK | AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS | 是 |
| anthropic-algorithmic-art--external_network | controlled_risk_twin | external_network | ALLOW | BLOCK | AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT | 是 |
| anthropic-algorithmic-art--adversarial_timeout | controlled_risk_twin | adversarial_timeout | ALLOW | REVIEW | AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT | 是 |

## 可用于答辩的准确表述

本实验不是执行网络上已知恶意 Skill，而是从 OpenAI 与 Anthropic 官方仓库选取许可证清晰、人工确认低风险且含真实脚本的 Skill。系统先原样运行真实脚本，再在保留完整包和原始入口的条件下加入受控风险包装器。36 个包均在同一套安装前 Docker 沙箱中完成三轮试运行，记录可解释行为事件、容器安全门和清理证明。

受控风险孪生只证明系统对这些运行时行为的检测能力，不能据此声称上游官方 Skill 本身恶意。语言级钩子仍可能被刻意绕过；Docker 隔离是安全边界，动态遥测不是内核级完整行为监控。

## 证据文件

- `run_manifest.json`：工具、配置、来源与运行环境哈希
- `static_results.jsonl`：36 个包的静态结果
- `dynamic_results.jsonl`：36 个包的动态摘要
- `dynamic_results/*.json`：逐包完整容器、事件、安全门与清理证据
- `metrics.json`：冻结指标的机器可读结果
- `acceptance.json`：按预先阈值计算的验收结论
