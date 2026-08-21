# M3：静态审计开发完成与冻结报告

日期：2026-08-21  
冻结候选：`2026-08-21-static-audit-dev-freeze-v5`  
适用对象：通用政企智能体平台中的 Skill、MCP 声明与 Python 依赖清单  
结论：**静态审计工程开发已完成，进入一次性封存回归前的冻结状态；600 条回归集仍未打开。**

## 1. “静态审计完成”的含义

本报告中的完成，是指当前比赛原型承诺的静态范围已经形成闭环：输入校验、厂商扫描、自研补强、覆盖缺口、统一 Finding、准入策略、结果留痕、SBOM 导出、自动测试和开发证据均已接通。它不表示能够发现所有未知攻击，也不表示替代运行时沙箱、人工代码审查或生产安全运营。

本阶段自动门禁不调用大模型。高危判断均来自确定性规则、有限 AST/变量流和显式策略，便于复现与申诉；大模型后续只能作为人工复核辅助，不能在没有证据约束时直接改变 `ALLOW/REVIEW/BLOCK/UNKNOWN`。

## 2. 完成后的统一链路

```text
Skill ZIP
  ├─ 安全解压、文件数/大小/路径边界
  ├─ Cisco Skill Scanner
  ├─ Aegis 攻击链、敏感流、不可信执行流、政企控制规则
  ├─ 静态覆盖证明（未解析对象显式 REVIEW）
  └─ Network / Filesystem / Command INFO 上下文

MCP JSON
  ├─ JSON 结构与对象数量边界
  ├─ Cisco MCP Scanner（离线静态对象）
  └─ Aegis Tool / Prompt / Resource 能力与权限策略

requirements.txt
  ├─ pip-audit 已知漏洞
  ├─ 版本、哈希、来源、索引和外部 include 完整性检查
  └─ CycloneDX SBOM（声明安装集合）

全部 Finding → YAML 准入策略 → ALLOW / REVIEW / BLOCK / UNKNOWN
                         └─ policy_trace、JSON/Markdown/SBOM 导出、SQLite 历史
```

扫描失败、超时、报告缺失、未知严重度或策略配置错误均不会静默变成 `ALLOW`。

## 3. 规则清单

规则注册表位于 `config/aegis_rule_registry.json`，共 **97 个**唯一 Aegis 静态规则 ID。自动测试从分析器源码抽取所有 `AEGIS_*` 字符串并与注册表双向比对，防止漏登记和幽灵规则。

| 规则族 | 数量 | 决策作用 | 主要范围 |
|---|---:|---|---|
| Aegis Static | 9 | REVIEW/BLOCK | 下载—解码—执行、管道入 Shell、持久化 |
| Sensitive Flow | 2 | BLOCK | 凭据、环境集合、敏感文件进入外发 payload |
| Untrusted Exec Flow | 3 | BLOCK | Tool/HTTP/CLI/模型输入进入 Shell、动态程序或动态导入 |
| Enterprise Controls | 12 | REVIEW/BLOCK | 权限、审计清除、安全控制、破坏操作、TLS、SSRF、元数据、反序列化 |
| Static Coverage | 8 | INFO/REVIEW | 超大代码、嵌套归档、二进制、未知语言、解析/解码/链接缺口及摘要 |
| Dependency Integrity | 8 | INFO/REVIEW/BLOCK | 锁定、哈希、直接来源、索引、include、未解析条目及清单摘要 |
| MCP Policy | 8 | INFO/REVIEW/BLOCK | 任意命令、文件根、URL、通配权限、指令覆盖、敏感/明文资源 |
| 三类 Context | 47 | INFO-only | 网络、文件、命令行为的声明、方向、来源和保护措施解释 |

INFO 规则只解释，不改变准入；MEDIUM 进入人工复核；HIGH/CRITICAL 阻断。严重度选项与决策作用也在注册表中固定。

## 4. E01—E10 完成状态

| 编号 | 能力 | 已完成内容 | 开发证据 | 状态 |
|---|---|---|---|---|
| E01 | 敏感数据外发 | Python AST、有限跨函数摘要、JS/TS 受限传播；正常认证头保护 | 120 条中补出 1 条恶意 `ALLOW→BLOCK`，normal 升级 0 | 完成 v1 |
| E02 | 不可信输入执行 | Tool/HTTP/CLI/模型来源关联 shell/eval、动态程序和模块 | v1 误报保留；v2 normal 升级 0，开发集无新增正例 | 工程完成，召回证据有限 |
| E03 | 权限过宽/提升 | world-writable、Skill wildcard、IAM/K8s/sudo wildcard、特权容器宿主访问 | 纳入 Enterprise v2；正常升级 0 | 完成 v1 |
| E04 | 安全控制与审计篡改 | 防火墙/EDR/SELinux 等关闭，审计规则或日志清除 | 确定性 CRITICAL 规则与正反测试 | 完成 v1 |
| E05 | 无保护破坏操作 | 递归删除、格式化、数据库清空；识别确认、dry-run、边界和受控临时目录 | Enterprise v1 发现控制误升级并保留；v2 校准通过 | 完成 v1 |
| E06 | 传输与 SSRF | TLS 校验关闭、明文敏感传输、不可信 URL、云元数据 | HIGH 规则与正常对照 | 完成 v1 |
| E07 | 覆盖证明 | 所有 Skill 输出覆盖摘要；不可解析/不可检查对象显式 Finding | 120/120 有摘要；1 个 Python 解析缺口，不改变既有决定 | 完成 v1 |
| E08 | 不安全反序列化 | pickle/dill/marshal、UnsafeLoader 等有限识别，正常 safe loader 对照 | Enterprise v2 正常升级 0 | 完成 v1 |
| E09 | 依赖完整性/SBOM | 精确 pin、SHA-256、URL/VCS/本地源、额外/明文索引、include；CycloneDX 导出 | Platform v3 18/18；真实旧 urllib3 漏洞链路通过 | 完成 v1 |
| E10 | MCP 能力策略 | 任意命令、无根目录文件能力、无限制 URL、通配权限、指令覆盖、敏感/明文 URI | v1 安全短语误报保留；v2 校准；v3 18/18 | 完成 v1 |

E02 的结论必须保持克制：机制测试和当前零误伤成立，但可见开发集没有新增 E02 正例命中，不能声称召回已提高。

## 5. 关键开发结果

### 5.1 Enterprise Controls v2

- 开发样本：120；
- 命中样本 / Finding：16 / 17；
- 非 normal 决策升级：10；normal 决策升级：**0**；
- 20 条正确控制变化：**0**；旧层等价：120/120；样本哈希变化：0；
- 结果：`supported_on_development_set`。

v1 曾把三个本来正确的 REVIEW 控制升级到 BLOCK；失败产物保留。v2 将 world-writable、通用无保护破坏操作和通用不安全反序列化校准为 MEDIUM，没有按 case ID 放行。

### 5.2 Static Coverage v1

- 120/120 产生覆盖摘要；
- 发现 1 个 `AEGIS_STATIC_PYTHON_PARSE_FAILED`；
- normal 升级、正确控制变化、旧层差异、哈希变化均为 0；
- 回归集打开数为 0。

覆盖 Finding 的含义是“当前分析器不能证明已检查”，不是“已发现恶意”。这避免把跳过、解析失败或二进制载荷误报为安全。

### 5.3 Dependency / MCP Platform Controls v3

- 18/18 冻结微用例通过；安全哈希锁和有边界 MCP 对照保持 ALLOW；
- 重复分析确定性差异为 0；
- Cisco MCP 真实冒烟：6 个对象成功返回；
- `pip-audit` 真实冒烟：1 个旧版 urllib3 组件返回 14 条当日漏洞记录；
- 密封回归打开数为 0。

漏洞条数会随上游数据库更新，不应当作固定算法指标；固定验收点是工具完成、已知风险不少于 1、Aegis 完整性层与 SBOM 同时产出。

## 6. SBOM 和传递依赖边界

依赖任务的数据契约升级到 `1.2`，新增可选 `sbom`。可使用：

```text
GET /api/v1/scans/{job_id}/export?format=sbom
```

导出为 CycloneDX 1.5 JSON。当前 SBOM 有三条必须保留的限定：

1. 清单范围是 requirements 中的**声明安装集合**；分析器不猜测某项是直接还是传递依赖；
2. 静态过程不运行 pip resolver、不安装包，`transitive-resolution-performed=false`；
3. `transitive-graph-completeness=not-proven`，只有声明条目的 pin/hash 完整性可以被证明。

政企交付建议上传由批准流水线生成、完全展开且带 SHA-256 的锁文件。若仍使用递归 `-r/-c`、版本范围、无哈希或外部来源，系统进入 REVIEW/BLOCK，不把不完整图谱说成完整 SBOM。

## 7. 安全与工程约束

- Skill：最多 500 个文件；安全相关单文件 1 MiB、累计 5 MiB；覆盖层对超限/未知对象显式告警；
- MCP：每类最多 500 个对象、单 JSON 1 MiB；静态阶段不连接或调用 MCP Server；
- 依赖：manifest 最大 1 MiB、2,000 个逻辑行；不安装、不导入依赖；
- Finding ID 基于规范化证据确定性生成；高风险证据不保留凭据值、完整 URL 或原始 MCP 内容；
- Cisco 与 `pip-audit` 的成功日志不保留临时绝对路径或完整 JSON，只留结果数、Finding/漏洞数和退出码；
- 全部过程使用 CPU，不需要 GPU。

## 8. 明确未覆盖的范围

以下内容不属于本次“静态 v1 完成”的对外承诺：

- 二进制反编译、嵌套归档递归解包和混淆代码还原；系统会给出覆盖缺口；
- npm、Maven、Go、Rust 等其他生态的漏洞数据库和 SBOM；当前依赖层是 Python requirements；
- 通过真实 MCP Server 握手验证运行时授权、响应内容和工具副作用；
- 复杂跨文件、反射、动态语言、框架封装和运行时数据流的完全语义证明；
- 用大模型自动给出最终准入决定；
- 在没有 Docker/VM/远程沙箱时执行第三方 Skill。

这些限制不会静默隐藏：能静态识别的缺口进入 Finding，超出输入/分析预算的任务失败闭锁。

## 9. 验证和复核命令

```powershell
# 后端全量
& '..\.runtime_mcp313\Scripts\python.exe' -m pytest backend\tests -q

# 前端客户端与生产构建
Set-Location frontend
pnpm test
pnpm build

# E03-E08 开发评估
& '..\.runtime_mcp313\Scripts\python.exe' tools\evaluation\run_enterprise_controls_development.py
& '..\.runtime_mcp313\Scripts\python.exe' tools\evaluation\run_static_coverage_development.py

# E09-E10 开发评估
& '..\.runtime_mcp313\Scripts\python.exe' tools\evaluation\run_platform_static_controls_development.py

# 最终开发冻结（真实四类预置扫描 + 源码哈希）
& '..\.runtime_mcp313\Scripts\python.exe' tools\evaluation\freeze_static_audit_development.py
```

实验目录不可覆盖。失败轮次和存在剩余问题的冻结候选均保留，新校准使用新的 run ID。freeze v1 功能门通过但成功日志仍含内部临时路径；v2 清除了路径但 Cisco Skill 单结果报告的日志计数仍显示为0；v3同时验证最小留存与计数准确性；v4把后端、前端和生产构建验证纳入冻结产物并扩大哈希清单，但摘要标题仍写死为v1；v5只修正自描述标题，作为最终开发冻结候选。

## 10. 当前冻结决策与下一道门

静态代码、规则、契约和开发证据满足冻结条件。下一道门只有一项：在用户明确授权后，对 600 条封存 Skill 回归集执行一次最终评估，产出独立的 normal 回退、恶意召回、F1/coverage、差分规则和哈希证据。运行前不再依据回归内容改规则；若结果失败，应如实报告并建立下一版本，不能回看后覆盖本次冻结。

因此，可向老师汇报：**静态审计开发已完成并冻结候选；独立回归尚未执行，最终泛化指标待封存集揭盲。**
