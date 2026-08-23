# D3 MCP 协议调用与 Marker 证据闭环实验 v1 计划

## 1. 节点与目标

- run id：`2026-08-23-mcp-protocol-marker-dev-v1`
- 分支：`dynamic-audit-v1`
- 实验层级：`auxiliary/dev`
- 父运行：Docker 安全后端 `2026-08-22-docker-safety-backend-dev-v2`
- 静态基线：`2026-08-22-static-audit-regression600-v1`（只读，不改变最终判定）
- 节点目标：在固定 Docker 安全边界内，以真实 MCP stdio/JSON-RPC 顺序执行自建服务，并仅在 `tools/call` 后形成政企公文 Marker 源到汇证据。
- 成功后的下一步：增加系统调用/文件变化级遥测，再接入经审核的第三方目标。
- 失败后的下一步：按协议实现、Docker 环境或证据关联三层分类修复，不扩大执行对象。

## 2. 研究合同

- 研究问题：静态 Trigger Plan 能否引导一个受控 MCP 目标完成 `initialize -> notifications/initialized -> tools/list -> tools/call`，并在工具真实读取模拟政企公文后形成脱敏 Marker 证据？
- 研究类型：确定性工程机制验证。
- 研究目标：证明“协议真实调用”和“敏感源到工具输出”的证据可以关联，同时不改变静态审计最终决策。
- 零假设：协议顺序不完整、工具 Schema 不合法、Marker 在调用前已泄漏、调用后未形成证据、Docker 安全门退化、原始 Marker 被报告保留或容器清理失败中的任一项成立。
- 备择假设：协议顺序与 Schema 校验均通过；`tools/list` 基线无 Marker；`tools/call` 后恰有 1 个 Base64 Marker witness；静动态关联为 `confirmed`；所有 Docker 安全门、脱敏门和清理门通过。
- 最强替代解释：输出只是 fixture 预先打印的字符串，而不是 MCP 工具读取诱饵文件产生。为排除此解释，服务端必须在初始化时创建诱饵文件，但仅允许 `tools/call` 处理器读取并返回；工具清单和初始化响应不得含 Marker。

## 3. 基线与可比边界

- 动态安全基线：固定 Python 镜像 digest、`--pull never`、`network none`、只读根、UID/GID 65532、drop all capabilities、no-new-privileges、资源限制、单个哈希锁定脚本挂载和精确容器清理。
- 动态证据基线：Marker v2 的生成、变换识别、脱敏 witness 与静动态关联定义保持不变。
- 数据：1 个自建、哈希锁定的 MCP fixture；第三方样本读取/执行均为 0。
- 不做数值优越性比较，本实验只新增协议层机制证据。
- 结果仅适用于该受控 fixture，不等价于已证明任意 MCP Server 安全或容器不可逃逸。

## 4. 决策指标（必须全部出现）

- `protocol_steps_passed` / `protocol_steps_total`
- `mcp_initialize_success`
- `mcp_tools_list_success`
- `mcp_schema_valid_calls`
- `pre_call_marker_witnesses`（目标 0）
- `post_call_marker_witnesses`（目标 1）
- `source_to_sink_witness_rate`（目标 1.0）
- `correlation_confirmed`（目标 1）
- `image_gates_passed` / `image_gates_total`
- `inspect_gates_passed` / `inspect_gates_total`
- `runtime_gates_passed` / `runtime_gates_total`
- `protocol_errors`、`timeouts`、`raw_marker_leaks`、`container_residuals`、`third_party_samples_executed`、`decision_changes`（目标均 0）

## 5. 最小代码变更图

| 路径 | 计划变更 | 必要性 | 风险控制 |
|---|---|---|---|
| `tools/dynamic/docker/fixtures/mcp_protocol_marker.py` | 自建 stdio MCP 服务与客户端 harness | 形成真实协议与工具调用 | 单文件、固定哈希、无依赖、无网络 |
| `config/docker_mcp_protocol_backend.json` | 锁定镜像、fixture 和安全配置 | 防止运行期扩权 | 不接受用户路径、命令或镜像 |
| `backend/dynamic_audit/mcp_protocol.py` | 验证协议转录、Marker 和关联 | 形成可复核证据 | 原始 Marker 只驻留内存，不落报告 |
| `tools/dynamic/run_mcp_protocol_audit.py` | 运行与固化实验产物 | 可复现、可汇报 | 拒绝覆盖已有证据 |
| `backend/tests/test_mcp_protocol.py` | 正常、错误、脱敏和清理测试 | 防回归 | Docker 调用使用模拟，真实运行另行记录 |

## 6. 执行设计

- MCP 规范：`2025-06-18`。
- stdio：一行一个 UTF-8 JSON-RPC 消息，stdout 不混入日志。
- 正常序列：`initialize` → `notifications/initialized` → `tools/list` → `tools/call`。
- 工具：`read_official_document`，输入 Schema 只接受 `{"action":"summarize"}`。
- 诱饵：由确定性 seed 在容器内生成并写入 `/workspace/decoys/official_document.txt`；`tools/list` 前不读取，`tools/call` 时读取并 Base64 返回。
- 最小证据：本地 fixture 单元测试通过。
- solid 证据：真实 Docker 运行、全部接受门通过、证据清单和哈希完整。
- maximum 证据：后续再增加 syscall/inotify 等遥测，不纳入本次合同。
- 冒烟命令：`python -m pytest backend/tests/test_mcp_protocol.py -q`
- 主运行命令：`python tools/dynamic/run_mcp_protocol_audit.py --run-id 2026-08-23-mcp-protocol-marker-dev-v1 --output artifacts/experiment/2026-08-23-mcp-protocol-marker-dev-v1`
- 预计资源：CPU ≤ 0.5、内存 ≤ 256 MiB、无 GPU、无云、无互联网、无镜像下载。
- 停止条件：全部决策指标达到目标且完整后端回归通过。
- 放弃条件：需要执行第三方代码、放宽 Docker 安全门、联网/拉取镜像或改变静态最终决策才能完成。

## 7. 预期输出

- `mcp_protocol_evidence.json`
- `metrics.json`
- `evaluation_summary.json`
- `run_manifest.json`
- `run.log`
- `bash.log`
- `summary.md`
- `artifact_manifest.json`

## 8. 规范依据

- MCP Lifecycle 2025-06-18：初始化必须是首次交互，随后客户端发送 `notifications/initialized`。
- MCP Transports 2025-06-18：stdio 以换行分隔 UTF-8 JSON-RPC，stdout 不得输出非 MCP 消息。
- MCP Tools 2025-06-18：通过 `tools/list` 枚举工具，通过 `tools/call` 调用，并验证工具输入。

## 9. 修订日志

| 时间 | 变更 | 原因 | 对可比性影响 |
|---|---|---|---|
| 2026-08-23 | 首次预登记 | Docker 安全基线已接受，进入 MCP 协议闭环 | 无；仅新增补充机制证据 |
| 2026-08-23 | pytest 临时目录改到实验目录 | 系统默认临时目录拒绝访问；首轮为 2 passed / 10 setup errors | 无；测试代码与指标未变，重跑 12 passed |
| 2026-08-23 | 正式命令改用 Python 完整路径 | shell 中短命令正常退出但没有生成输出；该次不计为实验 | 无；代码、配置和指标合同未变，完整路径运行形成 v1 证据 |
| 2026-08-23 | 完整回归改用项目运行时 | 系统 Python 缺少 FastAPI，测试收集失败 | 无；未安装/升级依赖，项目 `.runtime_mcp313` 得到 308 passed |
