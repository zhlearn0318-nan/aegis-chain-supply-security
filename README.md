# Aegis Chain：面向智能体生态的供应链安全原型

> 当前状态、发布判断和下一工程节点以 [`CURRENT_STATUS.md`](CURRENT_STATUS.md) 为唯一真值；阶段报告中的旧测试数和“下一步”仅代表当时快照。

Aegis Chain 是 XA-202620 赛题“供应链安全”方向的本地工程原型，面向通用政企智能体平台，对 Agent Skill、MCP 对象和 Python 依赖提供统一静态审查、证据归一化、准入策略和管理员可信样本动态验证。

当前系统已接入 Cisco AI Skill Scanner、Cisco AI MCP Scanner 和 `pip-audit`，并实现自研 Aegis Static、Network/Filesystem/Command Context，以及只运行自建哈希锁定 fixture 的 Docker/MCP 动态机制验证。

## 当前能力

- Skill ZIP：Cisco 静态/字节码/管道分析 + Aegis 静态关联规则；
- MCP JSON：Tool、Prompt、Resource 离线扫描；
- Python 依赖：CVE、GHSA、PYSEC 漏洞检查；
- 统一结果：Finding IR、SHA-256、任务历史、JSON/Markdown 导出；
- 准入策略：`ALLOW / REVIEW / BLOCK / UNKNOWN` 四态门禁，失败闭锁；
- 上下文证据：网络、文件系统和命令行为 INFO 解释；
- 管理员动态验证：固定 3 份自建 fixture，验证 7 类预期机制，不接受用户代码、路径或命令；
- 受控 MCP 动态闭环：MCP 2025-06-18 stdio 真实调用、政企 Marker 源到汇证据、Linux inotify/procfs 独立遥测和 Docker 失败闭锁。
- 动态任务控制：SQLite 持久 FIFO、全局单执行、活动/冷却去重、有界等待队列、429 和重启恢复。

最近冻结结果：

- SkillTrustBench v1.0：已完成 5,520 条全量 Cisco 静态基线，另建 120 条开发集和 600 条封存回归集；
- 管理员动态接口：3/3 fixture、7/7 机制，负面安全指标全部为 0；
- MCP Docker 受控遥测实验：82/82 接受门，独立文件读取确认 1、容器残留 0；
- 后端完整测试：341 passed；
- 前端 API 测试：10 passed；
- 前端生产构建：通过。

## 仓库结构

```text
.
├─ demo_web/              FastAPI + React 主系统
│  ├─ backend/            API、适配器、规则、策略与测试
│  ├─ frontend/           Vite/React 页面
│  ├─ config/             准入策略与固定动态 fixture 配置
│  ├─ tools/              数据准备、评测和验证工具
│  ├─ baseline/           冻结基线与开发/回归清单
│  ├─ docs/               对接文档、阶段报告和工作日志
│  └─ artifacts/          精选的可复核动态验证证据
├─ fixtures/              防御性 Skill、MCP 与依赖样例
├─ scripts/               Cisco 扫描调用与结果校验脚本
├─ docs/                  早期复现和工具调研材料
└─ results/               仅保留锁定依赖与精选复现摘要
```

`datasets/`、`third_party/`、Python 运行环境、Node 依赖、SQLite、缓存、日志和大规模扫描输出不会上传 GitHub。

## 本机运行

### 1. 准备运行环境

本项目当前在 Windows 11 上验证。Cisco 扫描器使用隔离运行时：

- `.runtime_skill`：Python 3.11 + Cisco AI Skill Scanner；
- `.runtime_mcp313`：Python 3.13 + Cisco AI MCP Scanner + `pip-audit`。

运行时和 Cisco 第三方源码不纳入仓库。首次使用可在任意仓库路径执行下列命令，脚本会从 Cisco 官方固定提交重建环境，并按哈希锁定依赖：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\bootstrap_runtimes.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\preflight.ps1" -SkipDynamic
```

完整说明见 [QUICKSTART.md](QUICKSTART.md)；锁定依赖清单位于 `results/*_locked_requirements.txt`。

### 2. 启动演示平台

```powershell
Set-Location .\demo_web
$env:AEGIS_ADMIN_TOKEN = "请替换为至少16位且仅本次会话使用的随机令牌"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1"
```

启动会先执行可移植预检并使用冻结的前端锁文件，不再依赖开发者个人目录。若只使用静态审计，可以不配置 Docker；若要求动态能力必须就绪，使用 `-RequireDynamic`。

访问：

- 页面：`http://127.0.0.1:8000`
- OpenAPI：`http://127.0.0.1:8000/docs`

管理员令牌只从服务端环境变量读取，前端只保存在当前 React 内存中。不要把真实令牌写入源码、文档、提交或截图。

### 3. 运行测试

```powershell
Set-Location .\demo_web
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run_tests.ps1"
```

也可以分别执行后端与前端检查，具体命令见 [demo_web/README.md](demo_web/README.md)。

## 关键文档

- [当前状态（唯一真值）](CURRENT_STATUS.md)
- [系统开发与使用说明](demo_web/README.md)
- [供应链模块对接与开发说明](demo_web/docs/Aegis_Chain_供应链安全模块对接与开发说明.md)
- [API v1 对接契约](demo_web/docs/API_V1_CONTRACT.md)
- [通用政企平台规则补强必要性](demo_web/docs/M3_通用政企智能体平台规则补强必要性说明.md)
- [最小安全动态 Fixture 报告](demo_web/docs/M3_SAFE_DYNAMIC_FIXTURE_V1_REPORT.md)
- [管理员动态验证 API/UI 报告](demo_web/docs/M3_ADMIN_DYNAMIC_FIXTURE_API_UI_REPORT.md)
- [M4 动态审计调研与实施计划](demo_web/docs/M4_DYNAMIC_AUDIT_RESEARCH_AND_IMPLEMENTATION_PLAN.md)
- [M4 MCP 协议调用与 Marker 证据闭环报告](demo_web/docs/M4_MCP_PROTOCOL_MARKER_V1_REPORT.md)
- [M4 MCP 内核辅助遥测报告](demo_web/docs/M4_MCP_KERNEL_TELEMETRY_V1_REPORT.md)
- [持续开发日志](demo_web/docs/WORK_LOG.md)

## 安全边界

- 仓库内攻击样例仅用于防御性静态检测，保留域名使用 `example.invalid`；
- 不要执行标记为 `must never be executed` 的 fixture；
- 管理员动态模块只运行仓库内自建、SHA-256 锁定的良性 fixture；
- 当前动态模块不是不可信 Skill 沙箱，不得用于执行第三方样本；
- 没有 Docker/VM/远程沙箱时，不扩大动态执行对象；
- 静态扫描未发现风险不等于绝对安全，`UNKNOWN` 必须默认不放行。

更多安全说明见 [SECURITY.md](SECURITY.md)。

## 项目状态

该仓库用于挑战杯“揭榜挂帅”赛道原型开发和队内协作，目前处于 M5 工程收敛阶段。P0-1/P0-2/P0-3 已完成，下一项为项目自身供应链卫生；生产发布仍为 NO-GO，完整差距见 `CURRENT_STATUS.md`。
