# M7 Skill 动态审计 20 样本稳定性回归报告

> 日期：2026-08-27
> 最终运行：`2026-08-27-skill-dynamic-regression20-v2`
> 结论：受控自建样本回归通过；生产发布仍为 NO-GO

## 1. 为什么做这次回归

此前 5 类样本 × 3 轮证明了 Docker 沙箱的最小闭环，但覆盖面不足以支撑“具备较完整的 Skill 动态审计能力”。本次把样本扩展到 20 个，并同时验证三件事：危险行为能否被识别、正常行为会不会被误阻断、同一行为重复运行是否稳定。

## 2. 覆盖矩阵

| 行为族 | 样本数 | 核心场景 | 预期策略 |
| --- | ---: | --- | --- |
| 良性对照 | 4 | 空操作、纯计算、工作区写入、回环请求 | ALLOW |
| 进程执行 | 4 | Shell、传输工具、Python 子进程、`os.system` | REVIEW 或 BLOCK |
| 外部网络 | 2 | 直接 IP、DNS | BLOCK |
| 编码/混淆 | 3 | 运行时拼接地址、Base64/Hex 诱饵外传 | BLOCK |
| 敏感数据 | 2 | 诱饵读取、原文诱饵外传 | BLOCK |
| 敏感路径 | 2 | `/etc/passwd`、SSH 凭据路径 | BLOCK |
| 动态加载 | 2 | 当前进程与 libc 的 `ctypes` 加载 | REVIEW |
| 资源滥用 | 1 | 确定性超时 | REVIEW |

每个样本只含 `SKILL.md` 和 `run.py`，文件集合及 SHA-256 均写入固定清单；内容变化会在启动 Docker 前被拒绝。

## 3. 执行与安全条件

- 20 个样本各执行 3 轮，共 60 个独立容器；
- 固定镜像 digest，`pull=never`，未下载新镜像；
- 容器断网、非 root、只读根、`cap-drop=ALL`、`no-new-privileges`；
- CPU、内存、PID 和临时盘均受限；Skill 与审计工具只读挂载；
- 每次启动前复核实际容器配置，每次结束后删除容器，整轮后再次查询残留；
- 未使用 GPU、云服务、互联网或第三方样本。

## 4. v1 暴露的标签缺口

v1 按预注册预期得到 60/60，但运行后工程审查发现：Python `os.system()` 本质通过系统 Shell 执行命令，原规则却把它当普通子进程，只给 `REVIEW`。这属于安全策略标签偏宽松，而不是运行失败。

处理方式：不覆盖 v1 原始证据；把任何 `os.system()` 事件提升为 `AEGIS_DYNAMIC_SHELL_SPAWN`、`CRITICAL`、`BLOCK`，增加单元测试后建立 v2，重新执行全部 60 次。该过程说明回归集不仅用于“证明通过”，也用于发现测试标签和规则本身的问题。

## 5. v2 最终结果

| 指标 | 结果 |
| --- | ---: |
| 场景 / 行为族 / 轮次 | 20 / 8 / 3 |
| 总执行数 | 60 |
| 决策正确 | 60/60 |
| 必需规则命中 | 60/60 |
| ALLOW / REVIEW / BLOCK | 12 / 12 / 36 |
| 良性误报 | 0 |
| 危险漏报 | 0 |
| 复核级错配 | 0 |
| 跨轮不稳定样本 | 0 |
| 遥测缺失 / 清理失败 / 容器残留 | 0 / 0 / 0 |
| 单次中位 / P95 / 最大耗时 | 2.790 / 3.496 / 4.753 秒 |
| 60 次总耗时 | 175.512 秒 |

修正后的 `os.system` 三次均由 v1 的 REVIEW 稳定变为 BLOCK，规则均为 `AEGIS_DYNAMIC_SHELL_SPAWN`。完整后端回归最终为 `422 passed, 1 skipped`；跳过项是当前 Windows 账户没有符号链接创建权限。

## 6. 当前已经可以主张什么

可以主张：在当前固定 Docker Desktop/Linux Engine、固定镜像和哈希锁定的 20 个自建 Python Skill 上，系统能稳定区分 ALLOW/REVIEW/BLOCK，给出对应动态规则证据，并在每次运行后完成清理；动态结果可以提高 OpenClaw 安装前的静态风险决策。

不能主张：60/60 不是真实世界检出率，不代表能安全运行任意未知 Skill，不代表 Python 审计钩子不可绕过，也不代表达到政企生产环境上线要求。

## 7. 仍缺哪些能力

| 缺口 | 为什么重要 | 建议优先级 |
| --- | --- | --- |
| 非 Python Skill（Shell、Node.js、原生二进制） | 通用智能体平台的 Skill 不会只有 Python | P1 |
| OOM、PID 上限等资源事件的真实归因 | 当前仅真实验证超时，分类器中的 OOM/PID 信号尚无端到端来源 | P1 |
| 压缩、加密、分片和跨进程诱饵外传 | 当前汇点只验证原文、Base64、Hex，主动规避仍可能绕过 | P1 |
| 动态 `exec/eval/marshal/pickle` 与审计干扰 | 当前原生加载有证据，但 Python 动态代码和主动绕过覆盖不足 | P1 |
| 内核级交叉证据 | Python hook 可被同进程对手规避，需要 Falco/eBPF 或同类旁证 | P1/P2 |
| 第三方安全语料与真实 Skill | 自建样本只能验证机制，不能给出外部泛化指标 | P1，需更强隔离后单独授权 |
| Windows 专属行为 | 当前目标容器为 Linux，无法覆盖 PowerShell、注册表和 Windows 凭据路径 | P2，按实际部署决定 |

比赛交付前建议优先做两项：先补 OOM/PID 与 Python 动态代码的受控样本和真实事件闭环；再在不放宽隔离条件的前提下，引入经过筛选、许可清晰的第三方良性/恶意 Skill 语料。Falco/eBPF 可作为研究增强，但不应破坏当前默认后端的演示稳定性。

## 8. 证据位置

- v1 原始证据：`demo_web/artifacts/experiment/2026-08-27-skill-dynamic-regression20-v1/`
- v2 最终证据：`demo_web/artifacts/experiment/2026-08-27-skill-dynamic-regression20-v2/`
- 固定样本清单：`demo_web/config/skill_dynamic_regression20.json`
- 回归执行器：`demo_web/tools/dynamic/run_skill_sandbox_regression20.py`
- 样本目录：`demo_web/tools/dynamic/fixtures/skill_sandbox_regression20/`
