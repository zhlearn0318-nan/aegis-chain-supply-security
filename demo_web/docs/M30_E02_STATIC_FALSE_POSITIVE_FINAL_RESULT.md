# M30 E02 真实生态静态误报治理最终结果

> 发布结论：`F3-v5` 通过三道冻结接受门，已接入 OpenClaw Skill 正式安装前静态准入流水线。

## 1. 最终方法

F3-v5 在 Cisco 与 Aegis 原始发现之后执行可解释的上下文处理。它不删除发现，而是对已证明属于模板、测试/示例、受限 notebook、纯文档局部链、无执行汇的通用命令文本、规范用户意图路由或固定 `sys.executable` 参数向量的发现降为 INFO，并保留原始严重度、上下文规则和原因。

完整远程执行、持久化、凭据/敏感数据外传、非可信 Shell/eval 与动态导入规则禁止降级。v5 同时删除了没有真实调用图支撑的“SKILL.md 未点名即不可达”推断。

## 2. 三道接受门

| 证据集 | 规模 | 关键结果 | 结论 |
| --- | ---: | --- | --- |
| 真实第三方完整 Skill | 40 | 低权限自动 ALLOW 83.3%；直接 BLOCK 0；无必要非放行较 F0 减少 57.1% | 通过 |
| SkillTrustBench regression600 | 600 | 恶意非放行召回 94.0%；较 F0 下降 0.5 个百分点；恶意 BLOCK 召回 81.5% 不变 | 通过 |
| MaliciousSkillBench source-disjoint train | 7,513 | 语义组件恶意非放行 24.40%；较 F0 下降 1.49 个百分点；冻结上限 2 个百分点 | 通过 |

三个证据集中的完整高危规则降级均为 0。规则注册表已登记 146 个静态规则 ID。

## 3. 失败结果如何推动修订

- v2 把训练集恶意非放行召回从 25.88% 降到 3.89%，下降 22.00 个百分点，否决；
- 根因是上下文短段落与语义分析器前后 14 行窗口不一致，割裂了正常调用描述和相邻恶意预执行指令；
- v3 统一窗口后下降收窄到 3.04 个百分点，仍否决；
- v4 仅认可规范 Skill 路由表达且要求窗口无强制、隐蔽、免确认和脚本标记，下降收窄到 1.49 个百分点；
- v5 修复历史保护规则名与当前实际输出不一致的问题，重新运行全部三道门后结果通过。

## 4. 产品行为

正式 `run_skill_static_pipeline` 现在统一应用 F3-v5，OpenClaw 上传扫描、安装策略二次扫描与动态审计前置静态扫描均复用该流水线。扫描报告会列出 `aegis-finding-context-v2`，被降级证据仍可在报告底部查看。

## 5. 证据与边界

- 真实 Skill 结果：`artifacts/experiment/2026-09-08-m15-e02-static-false-positive-v5/`；核心指标 SHA-256 `30b03d1bb7e4c82090edeaf69ef26c36d7ea1511a78677bd7822b20576f050a7`。
- regression600：`artifacts/experiment/2026-09-08-m15-e02-skilltrust-regression600-v3/`；指标 SHA-256 `63845c003076c3bb7290653062cf457b268831c8c87ef8f5b2036c8caaaf50be`。
- train 来源分组回归：`artifacts/experiment/2026-09-08-m15-e02-malicious-train-semantic-regression-v5/`；指标 SHA-256 `288cbd2660fda32ef897c4a62ed4634198bb514ae6eca9a1c2e9d595853eed56`。

MaliciousSkillBench train 是工程开发证据，不是新的独立盲测；已开封 test 不重新包装为盲测。SkillTrustBench regression600 包含 12 个父扫描失败样本，它们继续按 UNKNOWN 失败关闭。当前结果支持比赛版本发布候选，不等于生产环境零误报或零漏报。

## 6. 下一步

按 M15 顺序进入 E03：在既有 36 个真实第三方原型/受控风险孪生上比较动态审计 0、1、3 轮的增量、稳定性和耗时，静态 v5 保持冻结。
