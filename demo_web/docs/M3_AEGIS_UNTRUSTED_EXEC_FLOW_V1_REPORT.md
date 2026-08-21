# M3：Aegis Untrusted Execution Flow v1 实现与开发集报告

日期：2026-08-21  
分析器：`aegis-untrusted-exec-flow-v1`  
接受运行：`2026-08-21-aegis-untrusted-exec-flow-dev-v2`  
结论：**工程机制与零误伤门槛通过；当前开发集没有新增救援样本，检测增益证据不充分。**

## 1. 本轮解决的问题

通用政企智能体会把用户问题、Tool 参数、HTTP 请求、命令行参数和模型输出交给本地工具。如果这些外部输入直接进入 shell、`eval/exec`、动态模块导入或可执行文件选择，攻击者可能把普通业务能力转化为命令执行入口。

原有 Command Context 能解释 shell、argv 和参数来源，但固定为 `INFO`，不参与门禁。本轮新增独立的精确变量流分析器，只有证明“明确外部来源 → 变量传播 → 执行汇点”时才产生 `HIGH/CRITICAL` Finding。

## 2. 已实现规则

| 规则 ID | 严重度 | 高置信条件 | 门禁效果 |
|---|---|---|---|
| `AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL` | `CRITICAL` | 外部输入或模型输出进入 shell、`shell=True`、shell解释器命令参数、`eval/exec` | `BLOCK` |
| `AEGIS_UNTRUSTED_DYNAMIC_EXECUTABLE` | `HIGH` | 外部输入决定 `subprocess/spawn` 的可执行文件，而不是只作为后续argv参数 | `BLOCK` |
| `AEGIS_UNTRUSTED_DYNAMIC_IMPORT` | `HIGH` | 外部输入决定 `importlib.import_module/__import__` 的模块名 | `BLOCK` |

明确来源包括：

- Python `input()`、`sys.argv`、`argparse.parse_args()`和标准输入；
- HTTP request body/query/form/params 与路由处理函数参数；
- `@tool`、`@mcp.tool` 等 Tool 处理函数参数；
- 常见 LLM/Agent 调用返回值；
- JavaScript/TypeScript 的 `process.argv`、请求对象、交互输入与模型调用结果。

第一版支持 Python AST 有界传播、顶层函数返回和简单调用参数传播，以及 JavaScript/TypeScript 常见直接赋值传播。分析不执行或导入样本。

## 3. 正常场景保护

以下情况不触发 E02：

- 固定可执行文件，外部输入只作为独立 argv 数据参数；
- 固定常量命令，与同文件外部输入无变量关系；
- 只有来源和执行 API 共现，没有值传播；
- 测试与 fixture 目录中的攻击样例；
- 无法证明精确链路的命令上下文，继续保持 INFO-only。

Finding 只保存规则、严重度、相对路径、行号和规范化来源/汇点代码，不保存用户输入、Prompt、模型输出或命令正文。

## 4. 两轮开发集校准

### 4.1 v1：发现并保留正常误报

v1 完成 120 条开发集运行后命中 1 条 normal 样本、产生 2 个 Finding，使其从 `REVIEW` 升为 `BLOCK`。原因是分析器知道命令列表包含 CLI 输入，却没有保留“列表第一项是固定 Python 解释器、输入只位于后续argv”的容器形状，因此把整个列表误解为动态可执行文件。

v1 结果按合同保存在 `artifacts/experiment/2026-08-21-aegis-untrusted-exec-flow-dev-v1/`，结论为 `revise_analyzer`，没有删除或覆盖。

### 4.2 v2：通用形状传播修复

v2 增加固定首项可执行文件的形状传播，覆盖：

- 命令列表先赋值给变量再执行；
- 固定命令列表通过简单帮助函数传递；
- 多个已知调用点必须全部保持固定首项，才使用该缓解证据。

该修复不使用 case ID、项目名或文件名白名单；动态第一项、`shell=True`、shell `-c` 和 `eval/exec` 规则保持不变。

## 5. 测试与接受结果

### 5.1 自动测试

- E02 专项测试：`15 passed`；
- 完整后端测试：`169 passed`；
- 覆盖 Tool、HTTP、CLI、模型输出、跨函数传播、动态导入、Python/JavaScript，以及固定argv、常量命令、仅共现和测试夹具反例。

### 5.2 v2 的120条开发集结果

| 指标 | 结果 |
|---|---:|
| 开发集样本 | 120 |
| E02命中样本 / Finding | 0 / 0 |
| 非正常样本决策升级 | 0 |
| 正常样本决策升级 | **0 / 50** |
| 正确控制样本变化 | **0 / 20** |
| Cisco + Static + Sensitive Flow等价 | **120 / 120** |
| 样本哈希变化 | **0 / 120** |
| 回归集打开数 | **0 / 600** |
| E02平均耗时 | 28.51 ms/条 |
| E02最大耗时 | 225 ms/条 |

结果分类为 `mechanism_only_no_development_rescue`：机制测试和开发集安全门槛成立，但本开发集没有未被旧层处理的E02正例，不能据此证明新增召回。

## 6. 结果应如何汇报

可以陈述：

> 已实现不可信输入到shell、动态代码、动态可执行文件和动态导入的有界静态变量流，并通过15项正反测试；完成一次正常误报校准后，120条开发集的正常升级为0，旧层与样本哈希保持不变。

不能陈述：

- E02 已在开发集补出新的攻击样本；
- E02 已提高数据集整体召回率；
- 已证明对未知框架和跨文件调用有效；
- 已通过600条独立回归集。

这不是“规则无效”，而是“现有开发集无法回答召回问题”。后续需使用权威数据或自建但独立冻结的正例集，并最终由封存回归提供未见数据证据。

## 7. 局限性

- Python 主要覆盖顶层函数和简单参数传播，复杂类方法、闭包、别名和跨文件调用可能漏报；
- JavaScript/TypeScript 主要覆盖常见直接赋值，尚不是完整 AST 污点分析；
- 分析是有界、路径不敏感的，复杂分支与容器变换可能造成漏报；
- 当前只把明确装饰器、请求对象和常见模型调用视为来源，未知框架需增加适配器；
- 固定可执行文件不代表整个操作安全，危险权限、破坏参数和越权动作由 E03—E05 负责。

## 8. 复核入口

```powershell
..\.runtime_mcp313\Scripts\python.exe -m pytest backend\tests\test_untrusted_exec_flow.py -q --basetemp=artifacts\test_tmp\untrusted-exec
..\.runtime_mcp313\Scripts\python.exe -m pytest backend\tests -q --basetemp=artifacts\test_tmp\backend-all
..\.runtime_mcp313\Scripts\python.exe tools\evaluation\run_untrusted_exec_flow_development.py
```

接受证据位于 `artifacts/experiment/2026-08-21-aegis-untrusted-exec-flow-dev-v2/`；失败轮次位于相邻的 `dev-v1/`。

## 9. 下一步

进入 E03“通配符权限与权限提升”静态规则。开发集已经包含 `V_WILDCARD_PERMS` 诊断样本，可用于通用 Linux、Windows、IAM 和 Kubernetes 最小权限规则的可见开发验证；600条回归集继续保持封存。
