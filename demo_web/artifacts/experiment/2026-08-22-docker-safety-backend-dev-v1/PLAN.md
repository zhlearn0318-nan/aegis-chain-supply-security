# D2 Docker 安全执行后端开发实验计划

- run id：`2026-08-22-docker-safety-backend-dev-v1`
- 实验等级：`auxiliary/dev`
- 父基线：`2026-08-22-dynamic-marker-flow-dev-v2`，只读；静态回归基线继续冻结
- 研究类型：确定性工程安全门验证
- 研究问题：能否在不下载新镜像、不执行第三方样本且不改变静态决策的条件下，用 Docker Desktop Linux Engine 建立可复核、失败闭锁的动态执行后端？
- 零假设：任一关键配置或运行门失败，包括镜像身份不匹配、非 `network=none`、可写根、root 用户、有效 capability、未启用 no-new-privileges、输入可写、资源限制缺失、容器残留或最终决策变化。
- 备择假设：固定本地镜像和自建哈希锁定 probe 完成；配置门和运行门全部通过；策略违规、外网、第三方样本、容器残留和最终决策变化均为 0。
- 镜像：`public.ecr.aws/docker/library/python@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65`，本机已存在，强制 `--pull=never`。
- 数据：无外部数据集；只执行 1 个本项目自建的安全 probe。
- 统计计划：确定性机制验证，不做显著性检验，不报告恶意检出率。
- minimum：Docker Engine/镜像身份可验证，命令计划测试通过。
- solid：容器配置检查、实际行为反例、清理、完整后端测试和证据包全部通过。
- maximum：第三方 MCP/Skill 执行，本轮禁止。
- 停止条件：发生镜像拉取、网络模式不是 none、挂载 Docker Socket/项目根/用户目录、使用真实凭据、执行第三方代码、工作区外写入或静态决策变化。
- 放弃条件：需要 privileged、pid=host、host network、Docker Socket、管理员容器或关闭端点防护才能通过。
- 声明边界：只能证明当前 Docker 配置和自建 probe 的隔离门成立，不能证明容器能抵抗未知内核逃逸，也不能证明第三方样本安全。

## 最小代码变更图

| 路径 | 计划变更 | 目的 | 主要风险 |
|---|---|---|---|
| `config/docker_dynamic_backend.json` | 固定镜像、fixture、资源和安全参数 | 配置可审计、失败闭锁 | 配置被放宽 |
| `backend/dynamic_audit/docker_backend.py` | CLI发现、配置校验、create→inspect→start→cleanup | 执行前检查真实容器配置 | 命令注入、清理错误 |
| `tools/dynamic/docker/fixtures/security_probe.py` | 自建非恶意运行反例 | 验证UID、capability、NNP、只读根和挂载 | 被误解为恶意检测 |
| `backend/tests/test_docker_backend.py` | 命令、inspect、配置和拒绝测试 | 防止安全参数回退 | 只测结构未测Engine |
| `tools/dynamic/run_docker_safety_audit.py` | 真实 Docker 运行与证据导出 | 生成可复现开发证据 | 运行环境差异 |

## 关键门

1. 镜像必须由 digest 引用，ID 与配置一致，禁止 pull。
2. `network=none`、`read-only`、`cap-drop=ALL`、`no-new-privileges=true`。
3. 数字非 root UID/GID；PID、内存、CPU、超时上限。
4. 只挂载单个哈希锁定 fixture 文件且只读；不挂载目录、凭据或 Docker Socket。
5. `/workspace` 和 `/tmp` 仅为小容量 `noexec,nosuid,nodev` tmpfs。
6. create 后先 inspect；全部配置门通过才允许 start。
7. 只保留脱敏 JSON；无论成功、失败或超时都验证并清理本轮容器。
