# Aegis Chain 正式版 v0.2 发布说明

> 发布日期：2026-09-09  
> 发布类型：挑战杯“揭榜挂帅”赛道实验增强正式版  
> 目标环境：Windows 10/11、OpenClaw `2026.7.1-2`、Docker Desktop Linux Engine  
> OpenClaw 插件版本：`4.2.0`

## 1. 版本定位

v0.2 在 v0.1 的 OpenClaw 安装前准入闭环上，补齐了 M15 E01—E06 六组比赛证据，并将通过三道冻结接受门的静态误报治理接入正式流水线。该版本适合比赛提交、现场演示和研究复现，不等同于真实政企生产环境的商业安全产品。

## 2. 相对 v0.1 的主要变化

- 静态组件消融：量化 Cisco、Aegis 规则、语义、能力一致性、本地模型和轻量模型贡献；
- 真实生态误报治理：在真实Skill、SkillTrustBench regression600和MaliciousSkillBench train上通过冻结接受门；
- 动态轮次消融：确认保留 typical、edge、adversarial 三轮；
- 动态绕过鲁棒性：覆盖编码、路径拼接、间接调用、落地执行、延迟触发、父子进程、分步数据流和超时；
- OpenClaw端到端：完成36场景正常矩阵、并发互斥、依赖故障关闭和报告一致性验证；
- 错误分析：分析60个漏报和全部54个良性非ALLOW，形成7项有样本支持的后续方向；
- 仓库治理：Apache-2.0、Windows CI、README/状态同步与主分支保护。

## 3. 冻结结果

| 实验 | 核心结论 |
| --- | --- |
| E01 | 完整S5恶意非放行召回53.6%，轻量模型相对S4增加9.31个百分点且没有额外良性损失 |
| E02 | 真实低权限Skill自动ALLOW 83.3%，直接BLOCK 0；两套回归损失均小于冻结上限 |
| E03 | D3风险非放行30/30，D1为22/30；D3 P95为18.02秒 |
| E04 | 风险变形24/24非放行，预期证据24/24，安全对照24/24 ALLOW |
| E05 | 正常矩阵36/36通过，审计/API/PDF一致36/36，非放行安装0 |
| E06 | 114个样本全部完成可追溯归因，形成7项支持数不少于5的改进方向 |

最终本机回归：后端 `557 passed, 1 skipped`，OpenClaw插件 `19 passed`，前端 `10 passed` 且生产构建通过。

## 4. 关键入口

- 一键安装：`Install_Aegis_OpenClaw_Final.cmd`
- 当前状态：`CURRENT_STATUS.md`
- M15总表：`demo_web/docs/M43_M15_P0_EXPERIMENT_FINAL_SUMMARY.md`
- 完整实验计划：`demo_web/docs/M15_FUTURE_EXPERIMENT_PLAN_CONTROL_ABLATION_ROBUSTNESS_PERFORMANCE.md`
- 安全边界：`SECURITY.md`

## 5. 已知限制

- Docker Desktop故障时准入会安全拒绝安装，但自动恢复不保证成功；
- 动态遥测主要为语言级探针，不覆盖全部原生代码或内核级绕过；
- 已知真实恶意第三方Skill只做静态分析，未直接执行；
- 第二台洁净Windows/真实VM验收仍未完成；
- 本地审计哈希链不等价于外部WORM、可信时间戳或企业SIEM；
- 当前仍是单机、单用户比赛架构，生产SSO/RBAC、多租户、高可用未完成。
