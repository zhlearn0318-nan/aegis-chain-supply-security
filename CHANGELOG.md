# Aegis Chain 版本变化记录

本文件记录影响团队协作、部署或实验结论的主要变化。当前能力以 [`CURRENT_STATUS.md`](CURRENT_STATUS.md) 为准。

## v0.2 — 2026-09-09

- 完成 M15 E01—E06：静态组件消融、真实生态误报治理、动态轮次消融、绕过鲁棒性、OpenClaw 端到端和错误分析；
- 将 F3-v5 上下文误报治理接入正式 Skill 静态流水线，完整高危链禁止降级；
- 完成 Python、Node.js、Shell 八类简单变形的24组动态配对验收；
- 保留三轮动态策略，并完成36场景 OpenClaw E2E、并发互斥和三类依赖故障关闭验证；
- 修复 OpenClaw 安全中心对列表型上下文规则漏计问题，内置规则总数正确显示146；
- 后端完整回归更新为 `557 passed, 1 skipped`，OpenClaw 插件 `19 passed`；
- 增加 Windows GitHub Actions，覆盖后端、OpenClaw 插件、前端测试和生产构建；
- 项目许可证改为 Apache-2.0。

## main — 2026-09-05 团队协作快照

相对 `v0.1`，当前主线新增或完善：

- 论文驱动的 Skill 语义操纵、声明—实现一致性和 OpenClaw 控制面静态规则；
- 本地 Ollama/Qwen 语义复核以及保留的外部模型接口，模型结果不能单独形成 BLOCK；
- 纯指令、Python、Node.js、Shell 的三轮 Docker 安装前动态审计；
- 多运行时安全执行器的固定参数、哈希锁、超时、断网、只读和非 root 约束；
- MaliciousSkillBench Source-Disjoint test 全量 1,384 条三版本评测；
- 6 个官方真实脚本与 30 个受控风险孪生的 108 次容器动态主实验；
- OpenClaw“Aegis 安全中心”报告与审计合并、PDF 下载反馈和单入口交互完善；
- Docker Desktop 遗留套接字的可恢复修复和一键安装预检增强；
- 后端完整回归更新为 `507 passed, 1 skipped`，OpenClaw 插件为 `19 passed`，前端为 `10 passed` 且生产构建通过。

当前主线仍是研究与竞赛原型。生产 SSO/RBAC、外部 WORM/SIEM、多实例高可用、内核级强遥测和第二台洁净 Windows 验收尚未完成。

## v0.1 — 2026-08-31

- 首个挑战杯比赛正式版；
- 完成 Cisco Skill/MCP 与依赖扫描统一接入；
- 完成 OpenClaw 安装前准入、统一安全中心、规则管理、报告和哈希链审计；
- 完成 Windows 一键安装器和现场演示基线。

不可变发布说明见 [`RELEASE_V0.1.md`](RELEASE_V0.1.md)。
