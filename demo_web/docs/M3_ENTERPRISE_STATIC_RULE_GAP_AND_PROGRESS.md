# M3：政企场景静态规则缺口与开发进度

日期：2026-08-21  
范围：通用政企智能体平台的 Skill、MCP 与依赖供应链静态审计  
边界：本阶段只完善静态审计；600 条封存回归集继续保持未打开状态。

## 1. 当前结论

当前自研静态层共有 **97 个**规则 ID，已经形成 Skill、MCP 与依赖三条静态链路：

- `aegis-static-v1` 有 9 个会进入 `REVIEW/BLOCK` 的规则；`aegis-sensitive-flow-v1` 有 2 个、`aegis-untrusted-exec-flow-v1` 有 3 个精确数据流规则；
- Enterprise Controls 有 12 个政企控制规则，Static Coverage 有 8 个覆盖证明规则；
- Dependency Integrity 与 MCP Policy 各有 8 个规则，分别补足锁定/来源/SBOM和Tool/Prompt/Resource能力语义；
- Network、Filesystem、Command Context 共 47 个规则，全部固定为 `INFO`，只提供解释，不改变准入决策；
- MCP 保留 Cisco Scanner，并叠加 Aegis 自研能力/权限静态策略；
- 依赖扫描保留 `pip-audit`，已增加 pin、哈希、来源、索引、外部 include 和 CycloneDX SBOM；不执行 resolver，传递图完整性明确标为未证明；
- 准入策略当前主要按 Finding 严重度进行 `ALLOW/REVIEW/BLOCK/UNKNOWN` 映射。

因此，当前比赛原型的静态开发范围已闭环，状态为“开发冻结、封存回归待授权”。复杂跨文件语义、其他依赖生态、二进制反编译和 MCP 运行时授权仍是后续版本边界，不在 v1 完成声明中。

## 2. 当前已有强项

| 风险方向 | 当前能力 | 状态 |
|---|---|---|
| 下载—解码—执行 | 远程获取、编码解码与执行汇点关联 | 已实现、开发集已验证 |
| 远程内容直接进入 Shell | `curl/wget/iwr/irm` 等进入命令解释器 | 已实现、开发集已验证 |
| 系统持久化 | 计划任务、系统服务、启动项/Profile写入 | 已实现、开发集已验证 |
| 敏感数据外发 | 凭据/环境/敏感文件经变量传播进入外发payload | v1已实现、开发集已验证 |
| 不可信输入执行 | Tool/HTTP/CLI/模型输出进入shell、eval、动态程序或模块 | v1已实现；机制测试通过，开发集无新增正例 |
| 网络上下文 | 声明、读写方向、敏感源邻近、认证用途 | 已实现，INFO-only |
| 文件上下文 | 读写、敏感路径、系统路径、删除、递归修改 | 已实现，INFO-only |
| 命令上下文 | Shell/argv、参数来源、危险命令、测试夹具 | 已实现，INFO-only |
| 失败闭锁 | 扫描异常与UNKNOWN不会静默放行 | 已实现 |
| 政企控制 | 通配权限、审计清除、安全控制、破坏操作、TLS/SSRF/元数据/反序列化 | 已实现、开发集已验证 |
| 覆盖证明 | 跳过、解析失败、二进制、归档与未知语言显式 Finding | 已实现、开发集已验证 |
| 依赖完整性 | pin、哈希、来源、索引、include、CycloneDX SBOM | 已实现、开发用例已验证 |
| MCP能力策略 | 任意命令、文件/URL边界、通配权限、指令覆盖、敏感资源 | 已实现、开发用例已验证 |

## 3. 政企场景规则缺口

| 编号 | 缺口 | 政企风险 | 当前状态 | 优先级 |
|---|---|---|---|---|
| E01 | 敏感数据源到外部汇点的精确数据流 | 凭据、业务数据或个人信息外传 | v1已实现有限精确变量流；复杂跨文件/框架传播仍待后续 | P0，首版完成 |
| E02 | 不可信输入进入Shell或动态执行 | Tool输入、用户输入、模型输出触发命令执行 | v1已实现；零误伤门槛通过，召回证据仍不足 | P0，工程完成/证据待补 |
| E03 | 通配符权限与权限提升 | IAM、Kubernetes、sudo、宿主机权限过宽 | Enterprise v1 已实现，v2开发集校准通过 | P0，完成 |
| E04 | 安全控制篡改与审计清除 | 关闭防火墙、EDR、审计或删除日志 | CRITICAL确定性规则已实现 | P0，完成 |
| E05 | 破坏操作缺少确认与回滚 | 递归删除、格式化、数据库清空 | 无保护操作进入REVIEW，保护条件有反例测试 | P0，完成 |
| E06 | TLS关闭、明文传输、SSRF与云元数据访问 | 内网探测、云凭据窃取、敏感数据明文传输 | HIGH规则已实现 | P0，完成 |
| E07 | 静态分析覆盖缺口 | 超大文件、二进制、嵌套归档规避扫描 | 所有Skill有摘要，缺口显式REVIEW | P0，完成 |
| E08 | 不安全反序列化链 | 网络/文件输入进入pickle、UnsafeLoader等 | 有限AST规则已实现，通用证据为REVIEW | P1，完成v1 |
| E09 | 依赖锁定、来源、哈希与SBOM | 依赖混淆、投毒、版本漂移 | Aegis完整性层和CycloneDX导出已实现；传递图未证明 | P0，完成v1 |
| E10 | MCP权限、资源URI与高危副作用 | 高权限Tool、Prompt诱导、敏感Resource | Aegis MCP Policy已实现 | P0，完成v1 |

## 4. 规则判定原则

后续规则不得通过“把所有INFO改成HIGH”实现。统一采用三级证据：

1. **精确链路证据**：能够证明同一变量或调用链从危险源进入危险汇点，允许进入 `HIGH/CRITICAL`；
2. **强关联但流向未证实**：多个关键行为在同一作用域出现，进入 `MEDIUM/REVIEW`；
3. **单一行为、声明或缓解措施**：继续使用 `INFO`，只帮助人工解释。

所有新规则必须同时包含正常对照，特别保护以下场景：

- Token 只用于 `Authorization` 或 `X-API-Key` 认证头；
- 固定可执行文件加参数数组；
- 已声明的只读网络和文件操作；
- 安全测试夹具中的恶意字符串；
- 有明确目标白名单、确认、dry-run和回滚机制的运维操作。

## 5. 开发顺序与状态

| 顺序 | 工作项 | 验收要求 | 状态 |
|---:|---|---|---|
| 1 | E01 敏感数据源→外部汇点 | 高置信规则、正反测试、开发集配对结果、正常样本零升级 | **v1完成（开发集验证）** |
| 2 | E02 不可信输入→Shell/动态执行 | 精确变量流；普通argv和固定工具不升级 | **工程完成，开发证据不充分** |
| 3 | E03 通配符权限与权限提升 | Linux、Windows、IAM、Kubernetes最小规则集 | **完成** |
| 4 | E04/E05 安全控制篡改与破坏操作 | 篡改审计直接阻断；无确认破坏操作进入复核 | **完成** |
| 5 | E06 不安全传输与SSRF | TLS关闭、明文敏感传输、云元数据访问 | **完成** |
| 6 | E07 静态分析覆盖证明 | 输出已分析/跳过文件及原因，核心文件失败闭锁 | **完成** |
| 7 | 冻结Skill静态规则 | 规则ID、严重度、版本、测试全部冻结 | **开发冻结候选完成** |
| 8 | 600条封存回归 | 只运行一次，输出Cisco与Aegis配对指标 | **封存，未打开** |
| 9 | E09 依赖静态供应链 | 声明安装集合、锁定、哈希、来源和SBOM；传递图边界显式 | **完成v1** |
| 10 | E10 MCP自研静态规则 | Tool/Prompt/Resource权限与副作用规则 | **完成v1** |

## 6. 本轮 E01 实验契约

- 运行 ID：`2026-08-21-aegis-sensitive-flow-dev-v1`；
- 实验级别：`auxiliary/dev`；
- 研究问题：高置信、变量级敏感数据流规则能否补充现有INFO邻近证据，同时不误伤正常API认证？
- 零假设：新增规则无法补出任何开发集非正常样本，或会升级正常样本决策；
- 备择假设：新增规则能识别至少一个现有开发集敏感外传案例，并且正常样本决策升级为0；
- 基线：Cisco全量冻结结果 + `aegis-static-v1`开发结果v4；
- 数据范围：120条可见开发集和新增合成正反测试；
- 禁止事项：不读取600条回归正文，不执行样本，不导入样本模块，不安装样本依赖，不联网；
- 主要指标：规则命中数、非正常决策升级数、正常决策升级数、正确对照退化数、样本哈希变化、规则耗时；
- 最小成功标准：专项测试通过、现有全量测试通过、正常开发样本零决策升级；
- 对外声明边界：开发集只支持机制与已知错误修复结论，不支持未知攻击泛化结论。

### 6.1 本轮实际结果

- 新增规则：`AEGIS_CREDENTIAL_IN_OUTBOUND_PAYLOAD`（CRITICAL）和 `AEGIS_SENSITIVE_DATA_TO_OUTBOUND_SINK`（HIGH）；
- 专项测试 `12 passed`，完整后端测试 `154 passed`；
- 120 条开发集命中 1 条恶意样本，决策由 `ALLOW` 升为 `BLOCK`；
- 50 条 normal 样本新增升级 0，20 条正确控制变化 0；
- Aegis Static v4 等价 120/120，样本哈希变化 0；
- 平均耗时 16.65 ms/条，最大 149 ms/条；
- 结果分类：`supported_on_development_set`；600 条回归集仍为 0 打开。

E01 的复杂类方法、跨文件、别名和框架封装覆盖列入后续增强，不在本轮开发集结果上夸大结论。

## 7. E02结果与决策

- 新增 `AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL`、`AEGIS_UNTRUSTED_DYNAMIC_EXECUTABLE`、`AEGIS_UNTRUSTED_DYNAMIC_IMPORT`；
- v1开发运行发现1条normal误升级，原因是固定解释器列表的后续argv含CLI输入；失败结果保留为`revise_analyzer`；
- v2增加固定首项可执行文件的赋值和简单帮助函数形状传播，不使用case ID例外；
- 专项测试`15 passed`，完整后端测试`169 passed`；
- v2在120条开发集命中0，正常升级0/50、控制变化0/20、旧层等价120/120、样本哈希变化0；
- 结果分类为`mechanism_only_no_development_rescue`：可确认工程机制和当前零误伤，不能确认召回提升；
- 600条回归集保持0打开；后续 E03—E10 已按本文第8节完成并进入冻结候选。

## 8. E03—E10 收口结果

- Enterprise Controls v1 首轮发现 3 个正确 REVIEW 控制被升级到 BLOCK，失败结果保留；v2 校准后 120 条开发集中非normal升级10、normal升级0、正确控制变化0；
- Static Coverage 对 120/120 输出摘要，显式发现 1 个 Python AST 解析失败，既有决策变化0；
- Dependency/MCP Platform Controls v1 出现 1 个安全短语误报并保留；v2修复，v3增加来源形式和SBOM边界后 18/18 通过；
- 规则注册表冻结 97 个唯一 ID，源码与注册表双向一致；
- 当前完整后端、前端和生产构建以静态完成报告的最终验证数字为准；
- 600条回归始终0打开。完整说明见 `M3_STATIC_AUDIT_COMPLETION_REPORT.md`。

## 9. 进度更新规则

每完成一类规则，都要更新：

1. 本文第5节状态；
2. 对应实现与开发集报告；
3. `WORK_LOG.md`；
4. `README.md`中的当前能力和证据索引；
5. `artifacts/experiment/<run_id>/`中的命令、指标、日志、清单和摘要。

## 10. 证据索引

- [5,520条全量基线报告](M2_SKILLTRUSTBENCH_FULL_REPORT.md)
- [开发/回归划分与规则缺口](M3_SKILLTRUSTBENCH_DEV_REGRESSION_AND_RULE_GAPS.md)
- [Aegis Static v1实现与开发报告](M3_AEGIS_STATIC_V1_IMPLEMENTATION_AND_DEV_REPORT.md)
- [Network Context报告](M3_AEGIS_NETWORK_CONTEXT_V1_REPORT.md)
- [Filesystem Context报告](M3_AEGIS_FILESYSTEM_CONTEXT_V1_REPORT.md)
- [Command Context报告](M3_AEGIS_COMMAND_CONTEXT_V1_REPORT.md)
- [Sensitive Flow v1实现与开发集报告](M3_AEGIS_SENSITIVE_FLOW_V1_REPORT.md)
- [Untrusted Execution Flow v1实现与开发集报告](M3_AEGIS_UNTRUSTED_EXEC_FLOW_V1_REPORT.md)
- [静态审计开发完成与冻结报告](M3_STATIC_AUDIT_COMPLETION_REPORT.md)
- [评委审查与后续完成清单](供应链安全模块_评委审查与后续完成清单.md)
