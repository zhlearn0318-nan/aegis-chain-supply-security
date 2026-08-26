# OpenClaw Install Policy v1 实验计划

- run id：`2026-08-26-openclaw-install-policy-v1`
- tier：`auxiliary/dev`
- branch：`openclaw-install-policy`
- baseline：当前 `dynamic-audit-v1` 静态扫描与 `admission_policy.yaml`

## 选定思路

实现不依赖 HTTP 的本地同步 OpenClaw `security.installPolicy` 适配器，直接复用现有 Skill 静态扫描核心；把现有决策映射到 OpenClaw protocol v1，并对所有输入、扫描和协议异常失败关闭。

## 研究问题

现有静态审计引擎能否在不改变冻结检测规则和策略语义的前提下，可靠地产生 OpenClaw 安装前 `allow/warn/block` 决策，并保证故障场景不放行？

## 假设

- H0：适配器不能稳定生成合规协议响应，或至少一种异常场景会失败放行，或复用扫描核心导致既有决策漂移。
- H1：协议正向/负向测试全部通过，安全/恶意内置 Skill 真实扫描分别为 allow/block，故障关闭率 100%，扫描前后树哈希无变化。

## 最小代码变更图

- `backend/openclaw_install_policy.py`：协议、哈希、映射、同步扫描。
- `tools/openclaw_install_policy.py`：CLI 入口。
- `backend/tests/test_openclaw_install_policy.py`：协议与故障关闭测试。
- `config/openclaw.install-policy.example.json5`：对接配置示例。

## 证据阶梯

- minimum：纯函数协议测试通过，所有异常返回 block。
- solid：真实安全/恶意 Skill 扫描分别 allow/block，完整后端回归通过。
- maximum：真实 OpenClaw 安装、警告确认、更新重扫和 `doctor --deep` 通过。

## 指标

- protocol_valid_rate
- negative_case_fail_closed_rate
- expected_decision_match_rate
- input_tree_unchanged_rate
- backend_regression_passed
- safe_skill_duration_ms / risky_skill_duration_ms

## 停止条件

- 修改冻结规则、策略或600条密封回归评价。
- 执行任何第三方或数据集样本。
- 扫描前后输入树哈希变化。
- 任一异常路径返回 allow。

## 预期输出

- `run.log`
- `results.json`
- `evaluation_summary.json`
- `run_manifest.json`
- `CHECKLIST.md`

