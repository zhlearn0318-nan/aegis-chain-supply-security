# M10：OpenClaw Skill P0/P1 实施与验收报告

> 状态：P0、P1 已完成本机工程验收
> 日期：2026-08-31
> 适用范围：OpenClaw Skill 安装前静态与隔离动态准入
> 决策原则：动态证据只能维持或提高风险，不自动推翻已确认的静态高危证据

## 1. 结论

本轮已把论文驱动的 P0 与 P1 方案接入 OpenClaw 正式安装准入链路，而不是停留在独立测试脚本：

1. P0 新增自然语言操纵、隐瞒行为、条件触发、不可见文本、声明—实现不一致、文件角色与 OpenClaw 控制面修改检测；
2. P0 接入本地 `qwen2.5:7b-instruct-q4_K_M` 语义复核，并保留受控外部大模型接口；大模型不能单独形成 BLOCK；
3. P1 从 Python 扩展为 Python、Node.js、Shell 三种脚本运行时，并为纯指令 Skill 提供不执行代码的语义审计路线；
4. P1 对每个脚本执行典型、边界、对抗三轮输入，采集脱敏行为证据；
5. Docker 容器启动前会核验镜像、挂载源、执行入口、完整参数和隔离策略，任一安全门不一致即失败关闭；
6. 正式 OpenClaw 请求经过 Cisco + Aegis 静态审计、P0、P1、单调证据融合后才返回安装决策。

因此，P0/P1 的代码、配置、真实 Docker 运行、OpenClaw 端到端链路、一键部署自检和回归证据已闭环。该结论不等于系统已达到政企生产环境上线标准。

## 2. P0 静态与语义增强

### 2.1 自然语言风险

| 能力 | 规则或机制 | 默认最高处置 |
| --- | --- | --- |
| 隐瞒用户 + 敏感读取/外传/执行/绕过确认 | `AEGIS_SEMANTIC_CONCEALED_RISKY_BEHAVIOR` | HIGH / BLOCK |
| 覆盖系统、平台或用户指令并关联危险行为 | `AEGIS_SEMANTIC_POLICY_OVERRIDE_CHAIN` | HIGH / BLOCK |
| 条件口令、延迟或特定触发条件关联危险行为 | `AEGIS_SEMANTIC_CONDITIONAL_RISK_TRIGGER` | MEDIUM / REVIEW |
| 不可见 Unicode 指令文本 | `AEGIS_SEMANTIC_INVISIBLE_INSTRUCTION_TEXT` | MEDIUM / REVIEW |
| 孤立、歧义控制语言 | 确定性规则 INFO；本地模型高置信复核后最高 MEDIUM | ALLOW 或 REVIEW |

分析器会排除 fenced code、示例、引用、测试标题和明确的安全禁止语境。例如“永远不要泄露凭据”不会仅因出现“泄露凭据”而被判断为恶意。Finding 不保存原始敏感段落，只保留特征代码、位置和哈希。

### 2.2 声明—实现一致性

系统解析 `SKILL.md` 引用关系，并把文件划分为 `REFERENCED / REACHABLE / TEST / EXAMPLE / UNKNOWN`。随后比较文档声明与代码实际使用的网络、文件、进程、凭据和 OpenClaw 控制能力：

- 可达代码出现未声明能力：MEDIUM / REVIEW；
- 修改 OpenClaw 配置、Hook 或策略：MEDIUM / REVIEW；
- 同时出现禁用、绕过安全控制的意图：HIGH / BLOCK；
- 测试或示例中的孤立危险词不直接提升为生产行为。

这部分落实了论文中 shadow feature 的高价值结论：风险不只取决于“有没有 Shell/网络”，还取决于“是否可达、是否声明、是否与功能一致”。

### 2.3 本地小模型与外部接口

默认配置使用本机 Ollama 与 `qwen2.5:7b-instruct-q4_K_M`。8 条小规模机制选择集上，Qwen 为 8/8，Mistral 为 3/8，因此选择 Qwen。该结果只用于本项目后端选择，不是通用模型排行榜，也不能外推真实生态准确率。

外部接口采用 OpenAI-compatible 形式，但默认关闭，并同时要求：

- `external.enabled=true`；
- `AEGIS_EXTERNAL_LLM_OPT_IN=1`；
- HTTPS；
- 主机位于允许列表；
- API Key 只从环境变量读取；
- 仅发送有界、脱敏片段与结构化特征，不发送完整 Skill 原文。

无论本地或外部模型，模型证据最高只能把歧义候选提升到 MEDIUM，不能独立产生 BLOCK。

## 3. P1 多运行时隔离动态审计

### 3.1 路由

| Skill 类型 | 动态路线 |
| --- | --- |
| 纯指令型 | 不执行代码；通过典型、边界、对抗三类语义检查门 |
| Python | 固定 Python 镜像，三轮运行，Python 行为钩子与诱饵证据 |
| Node.js | 固定 Node 镜像，三轮运行，预加载钩子采集进程、网络和文件证据 |
| Shell | 固定 Python 基础镜像，以 `/bin/sh -x` 三轮跟踪命令证据 |

入口只从 Skill 清单引用关系和受限发现规则中产生，最多三个入口，总时限 90 秒。

### 3.2 容器安全门

系统使用不可变 digest 和本地精确 Image ID，`pull=never`。容器先创建、检查、再启动。检查范围包括：

- `network=none`、只读根文件系统、非 root 用户；
- `cap-drop=ALL`、`no-new-privileges`、非 privileged；
- 独立 IPC/PID、64 PIDs、256 MiB、0.5 CPU；
- `/tmp` 与 `/workspace` 为 noexec/nosuid/nodev tmpfs；
- 仅有 `/skill` 和 `/aegis_tool` 两个精确只读挂载；
- 挂载源、目标、执行入口、完整命令参数和工作目录均与计划一致；
- 禁止 Docker socket、宿主根目录和额外挂载；
- 日志驱动关闭、restart=no、init=true；
- 执行结束按本次创建返回的精确容器 ID 清理，并再次查询残留容器。

语言级钩子与 Shell xtrace 提供可解释证据，但可能被主动绕过；Docker 安全门是执行隔离边界，也不等于虚拟机或内核级完整监控。

## 4. 决策融合

正式准入保留现有单调策略：

- 静态 BLOCK 不会被一次动态清洁降级；
- 动态发现诱饵读取、Shell 启动、传输工具、危险网络或文件行为时可以升级到 BLOCK；
- 动态执行异常、遥测不完整、配置不一致或 Docker 不可用时失败关闭；
- 纯指令 Skill 的语义路线不伪装成真实脚本执行。

这符合本阶段“暂不改变最终决策”的约束，也避免大模型或一次未触发行为误放已确认高危 Skill。

## 5. 验收结果

### 5.1 机制开发与回归

| 集合 | 结果 | 说明 |
| --- | ---: | --- |
| 开发集 | 20/20 | 论文机制派生的配对开发集 |
| 首次冻结回归观测 | 14/16 | 暴露两处真实缺陷：指令覆盖语法变体、OpenClaw 路径与写操作顺序 |
| 修复后同集复跑 | 16/16 | 验证缺陷修复，不作为独立泛化证据 |
| 新鲜回归 v2 | 12/12 | 修复后重新建立的配对留出集 |

首次失败没有被解释为“数据问题”，而是补充对应规则与单元测试后才复跑。以上集合用于证明机制闭环，不是外部权威数据集，不能据此宣称真实世界 100% 准确率。

### 5.2 真实 Docker 动态验收

6 个脚本 Skill 覆盖 Python、Node.js、Shell 的安全/恶意配对：

- 决策：6/6；
- 镜像与容器安全门：全部通过；
- 三轮输入证明：全部通过；
- 逐容器清理：全部通过；
- 标签复查残留容器：0；
- 总耗时：17,384 ms。

恶意样本分别命中诱饵敏感数据读取、Node Shell 启动和 Shell 网络传输工具启动；对应安全样本均放行。

### 5.3 OpenClaw 正式端到端验收

6 个样本通过正式协议请求进入安装前策略：

- 结果：6/6；
- 总耗时：41,533 ms；
- 安全 Python/Node/Shell：ALLOW；
- 恶意 Python/Node/Shell：BLOCK；
- 链路固定启用 `AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY=required`。

端到端脚本曾发现一次验收配置未显式启用动态必需模式的问题；修复后才生成当前 6/6 证据，避免把纯静态结果误称为全链路结果。

### 5.4 工程回归与部署自检

- 后端：`495 passed, 1 skipped, 1 warning`；
- OpenClaw 插件：`17 passed`；
- 独立前端：`10 passed`；
- 完整动态部署预检：`ready=true`、`dynamic_ready=true`、0 required failures、0 warnings；
- Docker Engine：29.7.2 / API 1.55；
- Cisco Skill Scanner、MCP Scanner、Python 锁、前端锁、两个不可变镜像、本地 Ollama 与 Qwen 均通过自检。

## 6. 一键部署变化

`install_openclaw_final.ps1` 已负责：

1. 检查或安装 Ollama；
2. 拉取并验证 Qwen 模型；
3. 拉取并验证 Python 与 Node 不可变镜像；
4. 写入 OpenClaw 插件的动态必需、本地语义、外部接口关闭环境；
5. 验证 Gateway 路由、插件注册和完整 preflight。

`-VerifyOnly` 已增加只读语义保护：Docker 或 Ollama 未就绪时只报告失败，不自动修复、启动或重启服务。专项契约测试与实际复测日志均确认未进入修复、插件安装或 Gateway 重启分支。

Docker Desktop 曾出现 `dockerInference` AF_UNIX 路径错误。仓库增加了可恢复修复脚本，只备份设置并移动对应运行时 socket 目录，不删除用户镜像或容器数据。本机修复后 Docker 与真实验收均通过。

## 7. 证据位置

- 论文对照与方案：`docs/M9_MALICIOUS_AGENT_SKILLS_PAPER_RULE_ENHANCEMENT_PLAN.md`
- 本地模型比较：`artifacts/p0p1/semantic-model-comparison-v1/`
- 开发集：`artifacts/p0p1/development-v1/`
- 修复后回归 v1：`artifacts/p0p1/regression-v1/`
- 新鲜回归 v2：`artifacts/p0p1/regression-v2/`
- 真实 Docker：`artifacts/p0p1/dynamic-acceptance-v1/`
- OpenClaw 端到端：`artifacts/p0p1/openclaw-e2e-v2/`
- 多运行时配置：`config/skill_dynamic_sandbox_v2.json`
- 语义模型配置：`config/skill_semantic_model.json`

## 8. 限制与后续 P2

P0/P1 已按本轮方案完成，但以下事项仍属于 P2 或生产化工作：

1. 使用论文公开数据集和现有 40 条真实第三方 Skill 集重新测量误报工作量与生态兼容性；
2. 增加 syscall/eBPF/ETW 等独立遥测，降低语言钩子被绕过的风险；
3. 引入真正的企业身份、权限分离、外部 WORM/SIEM 和可信时间戳；
4. 在第二台洁净 Windows VM 上完成换机验收；
5. 扩展更多运行时、包管理器安装阶段和原生二进制行为覆盖；
6. 建立人工复核标注闭环，持续校准模型与规则。

评委口径应为：**系统已完成可演示、可复核的 OpenClaw Skill P0/P1 安装前准入闭环；实际生产上线仍需 P2 控制面、独立遥测和外部生态评测。**
