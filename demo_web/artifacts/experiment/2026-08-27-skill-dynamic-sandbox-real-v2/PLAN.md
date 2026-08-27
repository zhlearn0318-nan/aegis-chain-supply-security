# PLAN：Skill 动态沙箱真实 Docker 重复验收 v2

## 1. 目标

- run id：`2026-08-27-skill-dynamic-sandbox-real-v2`
- 问题：M7 的规则与容器合同是否能在真实 Docker Desktop Linux Engine 上稳定区分良性与高危 Skill 行为？
- 假设：5 类自建、哈希锁定的 Python Skill fixture 连续运行 3 轮后，决策和关键规则保持正确，遥测与清理安全门全部通过。

## 2. 样本与预期

| 场景 | 预期决策 | 关键证据 |
| --- | --- | --- |
| 良性临时文件写入 | ALLOW | 无影响准入的动态规则 |
| 外部网络连接尝试 | BLOCK | `AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT` |
| 诱饵读取并发送到本地汇点 | BLOCK | `AEGIS_DYNAMIC_DECOY_ACCESS`、`AEGIS_DYNAMIC_DECOY_EXFILTRATION` |
| 启动 Shell | BLOCK | `AEGIS_DYNAMIC_SHELL_SPAWN` |
| 超出开发验收时限 | REVIEW | `AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT`、执行不确定证据 |

全部样本为项目自建；第三方样本执行数必须为 0。每个可执行文件和说明文件均绑定 SHA-256，内容变化时拒绝运行。

## 3. 安全合同

- 固定 digest 的本地 Python 镜像，`pull=never`；
- `network=none`、非 root、只读根文件系统、移除全部 capabilities；
- `no-new-privileges`，CPU、内存和 PID 数量受限；
- Skill 与审计工具只读挂载，临时工作区使用受限 tmpfs；
- 创建后检查容器实际配置，任一门不符不启动；
- 每次运行后删除容器，并在整轮结束后按后端标签再次查询残留。

## 4. 接受标准

- 5 个场景 × 3 轮 = 15 次执行全部通过；
- 决策正确 15/15；
- 良性误报、危险漏报、遥测缺失、清理失败和容器残留全部为 0；
- GPU、云服务、运行时镜像下载和第三方样本均不使用。

## 5. 结论边界

本实验只证明当前固定镜像、自建 Python fixture 和当前主机 Docker 配置上的确定性接受门。它不证明容器不可逃逸，不证明能安全执行任意第三方 Skill，也不替代 Falco/eBPF 或独立虚拟机级验收。
