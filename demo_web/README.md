# Aegis Chain：智能体供应链安全准入网关原型

本项目是 XA-202620 赛题“供应链安全”模块的本机原型。网页会真实调用已经复现的 Cisco Skill Scanner、MCP Scanner 和依赖漏洞审计链路，不使用伪造扫描结果。

当前已完成 M1.3 的可配置准入策略、`/api/v1` 和前端 v1 适配，并完成 M2 的 SkillTrustBench v1.0 全量 5,520 条评测。全量结果已冻结；另建 120 条开发集与 600 条封存回归集。M3 已实现 Aegis Static v1、三个 INFO-only Context、最小安全动态 Fixture v1，以及管理员专用异步动态验证 API/页面。动态模块只运行 3 份自建哈希锁定 fixture，不接收任意脚本、路径或命令，继续保持 INFO-only、决策变化 0，回归集仍封存。

## 一键启动

在 PowerShell 中进入本目录后运行。显式传入执行策略，可以避开部分 Windows 电脑默认禁止执行 `.ps1` 的问题：

```powershell
$env:AEGIS_ADMIN_TOKEN = "请替换为至少16位且仅本次会话使用的随机令牌"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1"
```

`AEGIS_ADMIN_TOKEN` 只由后端进程从环境变量读取。网页中的令牌只保存在当前 React 内存，刷新页面即消失；不要把真实值写进源码、Markdown、截图或汇报材料。未配置令牌时，静态扫描仍可使用，管理员动态接口会按安全策略返回 `503`。

停止服务：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\stop_demo.ps1"
```

只启动服务、不自动打开浏览器：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1" -NoBrowser
```

网页地址：`http://127.0.0.1:8000`

接口文档：`http://127.0.0.1:8000/docs`

## 自动测试

在本目录执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run_tests.ps1"
```

测试不会执行恶意样本，主要验证门禁决策、Cisco 结果归一化、ZIP 路径安全和 MCP JSON 拆分。

当前后端结果以本阶段冻结报告为准；可使用上述脚本一键复核。

前端 v1 客户端测试：

```powershell
Set-Location .\frontend
pnpm test
```

## 现在从哪里开始

- 开发排期：[`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md)
- 每步做了什么：[`docs/WORK_LOG.md`](docs/WORK_LOG.md)
- M1.3 策略配置说明：[`docs/M1_3_POLICY_CONFIG.md`](docs/M1_3_POLICY_CONFIG.md)
- API v1 对接契约：[`docs/API_V1_CONTRACT.md`](docs/API_V1_CONTRACT.md)
- 前端 v1 对接说明：[`docs/FRONTEND_V1_INTEGRATION.md`](docs/FRONTEND_V1_INTEGRATION.md)
- 固定的 Cisco 对照基线：[`baseline/cisco_static_baseline.json`](baseline/cisco_static_baseline.json)
- SkillTrustBench 数据审计：[`docs/DATASET_AUDIT_SKILLTRUSTBENCH.md`](docs/DATASET_AUDIT_SKILLTRUSTBENCH.md)
- SkillTrustBench pilot 基线：[`baseline/skilltrustbench_v1_0/BASELINE.md`](baseline/skilltrustbench_v1_0/BASELINE.md)
- M2 Cisco 静态基线报告：[`docs/M2_SKILLTRUSTBENCH_BASELINE.md`](docs/M2_SKILLTRUSTBENCH_BASELINE.md)
- M2 官方 556 条扫描报告：[`docs/M2_SKILLTRUSTBENCH_OFFICIAL_10PCT_REPORT.md`](docs/M2_SKILLTRUSTBENCH_OFFICIAL_10PCT_REPORT.md)
- M2 全量 5,520 条扫描报告：[`docs/M2_SKILLTRUSTBENCH_FULL_REPORT.md`](docs/M2_SKILLTRUSTBENCH_FULL_REPORT.md)
- M3 开发/回归与规则缺口报告：[`docs/M3_SKILLTRUSTBENCH_DEV_REGRESSION_AND_RULE_GAPS.md`](docs/M3_SKILLTRUSTBENCH_DEV_REGRESSION_AND_RULE_GAPS.md)
- M3 通用政企平台规则补强必要性说明：[`docs/M3_通用政企智能体平台规则补强必要性说明.md`](docs/M3_通用政企智能体平台规则补强必要性说明.md)
- M3 Aegis Static v1 报告：[`docs/M3_AEGIS_STATIC_V1_IMPLEMENTATION_AND_DEV_REPORT.md`](docs/M3_AEGIS_STATIC_V1_IMPLEMENTATION_AND_DEV_REPORT.md)
- M3 Network Context v1 报告：[`docs/M3_AEGIS_NETWORK_CONTEXT_V1_REPORT.md`](docs/M3_AEGIS_NETWORK_CONTEXT_V1_REPORT.md)
- M3 Filesystem Context v1 报告：[`docs/M3_AEGIS_FILESYSTEM_CONTEXT_V1_REPORT.md`](docs/M3_AEGIS_FILESYSTEM_CONTEXT_V1_REPORT.md)
- M3 Command Context v1 报告：[`docs/M3_AEGIS_COMMAND_CONTEXT_V1_REPORT.md`](docs/M3_AEGIS_COMMAND_CONTEXT_V1_REPORT.md)
- M3 最小安全动态 Fixture v1 报告：[`docs/M3_SAFE_DYNAMIC_FIXTURE_V1_REPORT.md`](docs/M3_SAFE_DYNAMIC_FIXTURE_V1_REPORT.md)
- M3 管理员动态验证 API/页面报告：[`docs/M3_ADMIN_DYNAMIC_FIXTURE_API_UI_REPORT.md`](docs/M3_ADMIN_DYNAMIC_FIXTURE_API_UI_REPORT.md)
- 90 条主实验原始证据：[`artifacts/experiment/2026-08-10-skilltrustbench-pilot90-v1/RUN.md`](artifacts/experiment/2026-08-10-skilltrustbench-pilot90-v1/RUN.md)
- 556 条扩大样本原始证据：[`artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/`](artifacts/analysis/2026-08-14-skilltrustbench-official10pct-cisco-v1/)
- 5,520 条全量原始证据：[`artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/`](artifacts/analysis/2026-08-14-skilltrustbench-full-cisco-parallel-v1/)
- 120/600 划分与脱敏分析证据：[`artifacts/analysis/2026-08-15-skilltrustbench-dev120-regression600-v1/`](artifacts/analysis/2026-08-15-skilltrustbench-dev120-regression600-v1/)

## SkillTrustBench pilot

从本目录运行：

```powershell
..\.runtime_mcp313\Scripts\python.exe tools\datasets\prepare_skilltrustbench.py
```

脚本固定 revision 并验证源对象，只解压 90 条 pilot。重复运行会复核缓存文件和 case tree hash，不会执行、导入或安装样本。原始数据保存在 `../datasets/skilltrustbench_v1_0/`；工作区根 `.gitignore` 已加入排除规则，但当前尚无有效 Git 仓库可做实际复核。

## SkillTrustBench 官方 556 条复核

先执行上面的基础数据导入，再运行：

```powershell
..\.runtime_mcp313\Scripts\python.exe tools\datasets\prepare_skilltrustbench_official_subset.py
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\run_skilltrustbench.py --mode official10 --output-dir artifacts\analysis\2026-08-14-skilltrustbench-official10pct-cisco-v1 --timeout-seconds 150
```

官方子集导入器固定结果仓库 revision、文件大小和 SHA-256。若运行中断，使用原命令并追加 `--resume`；恢复前会核对运行契约、完成前缀和样本 hash。若 Windows Defender 阻断真实恶意样本，不要关闭防护或设置排除目录，运行器会按失败闭锁记为 `UNKNOWN/abstain`。

## SkillTrustBench 全量 5,520 条复核

完整数据已固定在同一 audited refresh。先安全导入全量只读案例，再使用 4 路有界并发扫描：

```powershell
..\.runtime_mcp313\Scripts\python.exe tools\datasets\prepare_skilltrustbench_full.py
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\run_skilltrustbench.py --mode full --output-dir artifacts\analysis\2026-08-14-skilltrustbench-full-cisco-parallel-v1 --timeout-seconds 150 --workers 4
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\verify_skilltrustbench_run.py --output-dir artifacts\analysis\2026-08-14-skilltrustbench-full-cisco-parallel-v1 --output artifacts\analysis\2026-08-14-skilltrustbench-full-cisco-parallel-v1\verification.json
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\report_skilltrustbench_full.py
```

并发批次仍按固定 ID 顺序逐条落盘；每批最多 4 条在运行，发生样本 hash 变化或未知分析器会停止整批。全量导入中 61 条被端点防护阻断、8 条因 Windows 路径不兼容而无法完整还原，均未调用 Cisco，按 UNKNOWN 计入严格指标。

## 冻结基线并生成开发/回归集

```powershell
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\freeze_skilltrustbench_development.py
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\analyze_skilltrustbench_development.py
```

第一条命令冻结全量比较基线，并确定性生成 120 条开发集和 600 条标签均衡回归集。第二条命令只读取开发集文本，输出规范化特征与补强路线；不会执行样本，也不会打开回归样本正文。

## Aegis Static v1 自研静态增强

当前 Skill 扫描在 Cisco 结果之后追加独立的 `aegis-static-v1` 证据关联层，覆盖远程获取—解码—执行、远程内容直接进入解释器、内嵌编码载荷，以及计划任务、系统服务和启动位置持久化。Cisco 原始 Finding 不会被改写，Aegis Finding 继续进入统一 YAML 策略和 `policy_trace`。

开发集诊断命令：

```powershell
..\.runtime_skill\Scripts\python.exe tools\evaluation\run_aegis_static_development.py
```

当前接受结果为 `artifacts/experiment/2026-08-16-aegis-static-rules-dev-v4/`：目标漏报补出 21/36、T06 12/12、20 条正确对照零回退、50 条 normal 开发样本零决策升级，Aegis 平均耗时约 17 ms/条。v4 增加滑动窗口和命中上限，避免重复关键词导致组合爆炸，且与 v3 的逐案决策和规则集合差异为 0。该结果只用于开发诊断，600 条回归集仍保持封存。详细说明见 `docs/M3_AEGIS_STATIC_V1_IMPLEMENTATION_AND_DEV_REPORT.md`。

## Aegis Network Context v1 网络上下文旁路

Skill 扫描还会追加 `aegis-network-context-v1` 的 `INFO` 级旁路 Finding，把文档中的网络声明与实际网络读取、外发 sink、敏感来源和正常鉴权语境关联起来。它不会修改 Cisco Finding，也不会改变最终门禁。

最终开发诊断位于 `artifacts/experiment/2026-08-18-aegis-network-context-dev-v3/`：16/16 条网络误报获得上下文，15 条明确声明网络、1 条未声明；36/36 决策和 20/20 正确对照保持不变。平均耗时约 13 ms/条，完整测试 `100 passed`。详细说明见 `docs/M3_AEGIS_NETWORK_CONTEXT_V1_REPORT.md`。

## Aegis Filesystem Context v1 文件系统上下文旁路

Skill 扫描还会追加 `aegis-filesystem-context-v1` 的 `INFO` 级旁路 Finding，把顶层文档中的文件能力说明与源代码的读写、工作区/临时路径、敏感/系统路径、覆盖、删除、递归修改和路径边界保护关联起来。它不修改 Cisco Finding，也不改变最终门禁。

最终接受结果位于 `artifacts/experiment/2026-08-18-aegis-filesystem-context-dev-v2/`：8/8 条文件系统误报获得上下文，声明/未声明为 7/1；28/28 决策不变，20/20 正确对照不变。平均耗时 15.32 ms/条，完整测试 `112 passed`，600 条回归集仍未打开。详细说明见 `docs/M3_AEGIS_FILESYSTEM_CONTEXT_V1_REPORT.md`。

## Aegis Command Context v1 命令上下文旁路

Skill 扫描还会追加 `aegis-command-context-v1` 的 `INFO` 级旁路 Finding，区分命令能力声明、仅导入未调用、argv/非 shell、shell 字符串、固定/动态可执行文件、stdin、参数来源、安全测试夹具、只读业务命令和危险命令类别。它不修改 Cisco Finding，也不改变最终门禁。

最终接受结果位于 `artifacts/experiment/2026-08-18-aegis-command-context-dev-v2/`：6/6 条命令误报获得上下文，五类关键机制 5/5；26/26 决策不变，20/20 正确对照不变。平均耗时 20.58 ms/条，完整测试 `126 passed`，600 条回归集仍未打开。v1 中普通 JavaScript 模板字符串被误解为 shell 引号变量的问题已在 v2 收紧且保留两轮证据。详细说明见 `docs/M3_AEGIS_COMMAND_CONTEXT_V1_REPORT.md`。

## 最小安全动态 Fixture v1

独立 CLI 只运行 `config/safe_dynamic_fixtures.json` 中 SHA-256 锁定的三份自建良性 Python fixture，观测子进程、stdin、环境变量、工作区文件和 `127.0.0.1` 回环连接。它拒绝工作区外写入、workspace 外 chdir、链接创建、非回环地址、错误端口和非批准 Python 命令行；原始输入、环境值、网络载荷和 stdout/stderr 不进入证据。

最终接受结果位于 `artifacts/experiment/2026-08-18-safe-dynamic-fixture-dev-v2/`：3/3 fixture、7/7 机制检查，策略违规、超时、原始 token 泄露、互联网连接、样本读取/执行和决策变化均为 0；完整测试 `136 passed`。该工具是可信 fixture 的协作式观测器，不是不可信代码沙箱，也不得用于执行第三方 Skill。详见 `docs/M3_SAFE_DYNAMIC_FIXTURE_V1_REPORT.md`。

## 管理员动态验证 API 与页面

前端“管理员动态验证”区域调用三条受保护接口：创建任务、查询历史、查询详情。请求必须在 `X-Aegis-Admin-Token` 头中携带与服务端环境变量一致的令牌；创建接口拒绝任何请求体，因此无法传入代码、路径、fixture 配置或命令。任务工作区执行完即删除，SQLite 只保存脱敏事件、机制指标与逐 fixture 状态，令牌不会进入任务记录。

动态任务状态为 `queued / running / completed / failed`，但没有 `ALLOW / REVIEW / BLOCK` 字段。页面显示的“机制验证通过”仅表示内置 fixture 的预期观测均成功，不代表某个第三方 Skill 安全，也不影响静态准入结果。

## 自定义上传格式

### Skill

- ZIP 压缩包，最大 15 MB。
- 包内必须且只能包含一个 `SKILL.md`。
- 扫描器不会主动执行 Skill 脚本，只启用 Static、Bytecode 和 Pipeline。

### MCP

- JSON 顶层支持 `tools`、`prompts`、`resources` 或 `contents`。
- 可以同时上传 `requirements.txt`，系统会合并 MCP 内容风险和依赖漏洞结果。

示例：

```json
{
  "tools": [{"name": "search", "description": "Search public documents"}],
  "prompts": [],
  "contents": []
}
```

## 结果状态

- `ALLOW`：扫描执行完整，未发现超过阈值的风险。
- `REVIEW`：发现中低风险，需要人工复核。
- `BLOCK`：发现高危或严重风险。
- `UNKNOWN`：扫描器异常、超时、结果缺失或外部工具执行失败。

默认判定阈值位于 `config/admission_policy.yaml`。新结果使用数据契约 `1.1`，`policy_trace` 会记录实际使用的策略版本、命中规则、严重度、Finding ID 和可读原因。配置无效或尝试关闭失败闭锁时，系统不会降级为 `ALLOW`。

## 数据策略

- 上传文件只保存在系统临时目录。
- 扫描结束后删除原始文件。
- SQLite 只保存任务摘要、制品哈希、分析器状态和风险 Finding。
- 支持导出 JSON 和 Markdown 技术汇报摘要。

## 技术结构

```text
React + Vite
      ↓ /api/v1
FastAPI 扫描网关
      ├─ /api/v1 统一成功/错误契约
      ├─ Skill Scanner 独立运行时 + Aegis Static/Network/Filesystem/Command Context
      ├─ 管理员动态 Fixture API（固定内置样本、异步、INFO-only）
      ├─ MCP Scanner 独立运行时
      ├─ pip-audit 依赖链路
      ├─ YAML 准入策略与 policy_trace
      └─ SQLite 结果历史
```
