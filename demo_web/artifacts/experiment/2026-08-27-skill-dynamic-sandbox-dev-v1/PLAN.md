# PLAN：Skill 安装前动态沙箱 dev-v1

## 1. Objective

- run id：`2026-08-27-skill-dynamic-sandbox-dev-v1`
- selected idea：复用已验收的 Docker 安全底座，对静态 ALLOW/REVIEW 的 Python Skill 做 60–120 秒确定性行为采集；Falco 仅在兼容性门通过后作为内核旁证。
- research question：在不降低现有 Docker 安全门的前提下，能否让动态高危行为稳定改变 Skill 最终准入结果？
- null hypothesis：动态执行不能稳定生成可解释高危证据，或设施失败仍可能导致错误放行。
- alternative hypothesis：安全、外连、诱饵外传、Shell、超时样本能够被稳定区分，且失败闭锁、容器清理和决策单调性全部成立。

## 2. Baseline and comparability

- baseline：`2026-08-23-skill-runtime-closure-dev-v1`
- baseline gates：Docker 40/40；Skill 闭包 59/59；仅自建哈希锁定 fixture；动态不改变决策。
- experiment tier：`auxiliary/dev`
- primary acceptance：行为分类正确率、动态阻断数、错误放行数、容器残留、超时处理、观测完整性。
- comparability boundary：保留镜像锁定、非 root、只读根、无 capability、无外网和创建后 inspect；不得把 Falco 高权限授予目标容器。

## 3. Code translation plan

| Path | Planned change | Purpose | Risk |
|---|---|---|---|
| `backend/dynamic_audit/skill_sandbox.py` | 入口发现、Docker 运行、证据归一与动态决策 | 核心编排 | 任意路径或命令注入 |
| `tools/dynamic/docker/skill_sandbox/` | 固定父启动器与 Python 审计钩子 | 容器内采集 | 语言级钩子可被绕过 |
| `config/skill_dynamic_sandbox.json` | 镜像、哈希、资源、时间和规则合同 | 失败闭锁 | 配置放宽 |
| `backend/tests/test_skill_sandbox.py` | 安全、恶意、超时、路径和决策测试 | 防回归 | mock 与真实 Docker 偏差 |
| `backend/openclaw_install_policy.py` | 静态/动态单调融合 | 安装前准入 | 改变已有静态语义 |
| `backend/dynamic_audit/falco_backend.py` | 可选 preflight、JSON 解析与归一 | 内核旁证 | Docker Desktop/eBPF 不兼容 |

## 4. Execution design

- minimum：纯函数入口发现、事件归一、决策融合和命令安全测试通过。
- solid：真实 Docker 上安全/恶意/超时自建样本通过，容器残留为 0，动态高危升级 BLOCK。
- maximum：Falco preflight 通过并与语言级事件形成交叉证据。
- smoke：只执行自建良性和无害恶意行为 fixture，不执行公开第三方恶意 Skill。
- stop condition：目标容器需要 privileged、host PID、Docker Socket或真实主机目录时立即停止。
- abandonment condition：Docker Desktop 无法启动或 Falco modern eBPF 不兼容时，将 Falco 标记为 optional/inconclusive，不阻塞默认后端。

## 5. Expected outputs

- 设计文档、代码、配置和测试；
- `results.json`、`evaluation_summary.json`、`run_manifest.json` 和运行日志；
- 真实运行可用时保存 engine、镜像、配置和 fixture 哈希；
- 明确 `supported/refuted/inconclusive` 结论与下一步。

## 6. Revision log

| Time | Change | Reason | Impact |
|---|---|---|---|
| 2026-08-27 | Falco 从强制后端改为可选增强 | Docker Desktop Linux Engine 本次未能启动，不能验证 eBPF 兼容性 | 默认后端仍可开发；Falco claim 保持 inconclusive |

