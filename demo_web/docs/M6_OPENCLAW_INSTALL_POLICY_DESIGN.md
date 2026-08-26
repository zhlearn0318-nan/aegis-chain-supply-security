# M6 OpenClaw 安装前供应链准入设计文档

> 文档状态：已批准进入实现
> 设计版本：1.0
> 编制日期：2026-08-26
> 开发分支：`openclaw-install-policy`
> 对接对象：OpenClaw `security.installPolicy` protocol v1

## 1. 建设目标

本阶段将现有 Aegis Chain 静态审计能力接入 OpenClaw 的真实安装流程，在 Skill 或插件的源码已经暂存、但尚未写入正式安装目录时执行安全检查，形成以下闭环：

1. OpenClaw 暂存待安装源码。
2. OpenClaw 调用本机可信准入命令。
3. 准入命令同步调用现有 Cisco Skill Scanner 与 Aegis 静态增强层。
4. 现有准入策略生成 `ALLOW / REVIEW / BLOCK / UNKNOWN`。
5. 适配器转换为 OpenClaw `allow / warn / block`。
6. 危险、未知、超时和执行失败场景均阻止安装。
7. 后续将本次决策摘要写入审计记录，供管理界面查询。

本阶段不重新调整已冻结的检测规则、600 条回归集或评价指标，不把动态执行和大模型调用放入安装同步链路。

## 2. 依据与边界

### 2.1 官方协议依据

OpenClaw 官方 `security.installPolicy` 具备以下性质：

- 在安装或更新提交前执行。
- 覆盖 Skill 和插件安装/更新来源。
- 通过标准输入接收单个 JSON 对象。
- 通过标准输出接收单个 JSON 对象。
- 决策仅允许 `allow`、`warn`、`block`。
- 非零退出、超时、非法 JSON、协议错误和缺少必要理由均失败关闭。
- `openclaw doctor --deep` 可以执行合成安装探针。

参考：<https://github.com/openclaw/openclaw/blob/main/docs/tools/skills-config.md#operator-install-policy-securityinstallpolicy>

插件运行时的 `before_install` Hook 只作为可选辅助扩展，不作为本项目的企业级主准入边界。

参考：<https://docs.openclaw.ai/plugins/hooks>

### 2.2 本版本范围

M6 v1 必须完成：

- `targetType=skill` 的目录型暂存源码扫描。
- OpenClaw protocol v1 请求校验与响应生成。
- 现有 Skill 静态扫描核心复用。
- 现有本地策略复用及决策映射。
- 扫描前后文件树身份校验。
- 超时、异常、输入错误的失败关闭。
- 协议单元测试与真实本地扫描冒烟测试。

M6 v1 暂不承诺：

- 对任意已运行远程 MCP Server 的持续监控。
- 对所有 OpenClaw 插件包的完整 MCP 语义解析。
- 在安装同步链路中执行第三方代码。
- 云端服务、在线大模型或 GPU 依赖。
- 多租户、RBAC、TLS 和集中式任务调度。

插件/MCP 安装包识别列为 M6 v1.1；在支持之前，对 `targetType=plugin` 返回明确的 `block`，避免覆盖范围不明时放行。

## 3. 总体架构

```text
OpenClaw install/update
        │
        │ staged sourcePath + protocol v1 JSON
        ▼
openclaw-install-policy.py
        ├── 请求协议校验
        ├── 目标/路径边界校验
        ├── 扫描前 tree SHA-256
        │
        ▼
现有 run_skill_static_pipeline
        ├── Cisco Skill Scanner
        ├── Aegis Static
        ├── Sensitive Flow
        ├── Untrusted Exec Flow
        ├── Enterprise Controls
        ├── Static Coverage
        └── INFO-only Context analyzers
        │
        ▼
现有 admission_policy.yaml
        │
        ├── ALLOW   ──> allow
        ├── REVIEW  ──> warn
        ├── BLOCK   ──> block
        └── UNKNOWN ──> block
        │
        ├── 扫描后 tree SHA-256 复核
        └── OpenClaw protocol v1 JSON stdout
```

准入命令直接调用 Python 扫描核心，不依赖 FastAPI、前端、数据库或本地 HTTP 服务。现有 Web 系统在后续阶段只承担查询、解释和证据展示，不决定安装是否通过。

## 4. 对接协议

### 4.1 输入字段

适配器从标准输入读取 UTF-8 JSON。核心字段如下：

| 字段 | 要求 | v1 处理方式 |
|---|---|---|
| `protocolVersion` | 必须为数字 `1` | 否则阻断 |
| `openclawVersion` | 非空字符串 | 记录但不做版本排序 |
| `targetType` | `skill` 或 `plugin` | v1 仅放行扫描 `skill` |
| `targetName` | 非空字符串 | 用于理由和审计标识，不用于拼接路径 |
| `sourcePath` | 非空绝对路径 | 必须解析为现有目录 |
| `sourcePathKind` | `directory` | 其他类型阻断 |
| `source` | 可选对象 | 作为来源元数据，不信任其安全声明 |
| `origin` | 可选对象 | 只保留结构化摘要，不参与直接放行 |
| `request` | 可选对象 | 用于区分 install/update 和后续审计 |

输入大小在启动脚本层限制，适配器不接受多对象、JSON Lines 或尾随非空内容。

### 4.2 输出字段

标准输出只能写出一个 UTF-8 JSON 对象：

```json
{
  "protocolVersion": 1,
  "decision": "warn",
  "reason": "检测到需要人工复核的中风险静态发现。",
  "findings": [
    {
      "ruleId": "AEGIS_EXAMPLE_RULE",
      "message": "发现摘要",
      "severity": "warn",
      "file": "scripts/example.py",
      "line": 12,
      "evidence": "脱敏证据摘要"
    }
  ]
}
```

约束：

- `reason`、`message`、`evidence` 最长 1000 字符。
- OpenClaw 最多接收 100 条 Finding；v1 为确保 `warn` 不超过 4000 字符交互预算，只输出按严重度排序后的前 3 条精简 Finding，完整结果仍由本系统报告保存。
- 文件位置只输出相对于 `sourcePath` 的路径；绝不输出宿主机绝对路径。
- 不输出原始密钥、完整源码、请求全文或供应商扫描原文。
- 运行日志写入标准错误；标准输出不允许混入日志。

### 4.3 决策映射

| Aegis 决策 | OpenClaw 决策 | 说明 |
|---|---|---|
| `ALLOW` | `allow` | 扫描成功且只包含允许严重度 |
| `REVIEW` | `warn` | 安装停止，等待操作员确认并重新评估 |
| `BLOCK` | `block` | 命中 HIGH/CRITICAL 等阻断风险 |
| `UNKNOWN` | `block` | 未知严重度按失败关闭处理 |
| 扫描器异常 | `block` | 不因基础能力不可用而放行 |
| 扫描超时 | `block` | 返回稳定的超时规则编号 |
| 源码扫描前后变化 | `block` | 防止检查时替换攻击 |

## 5. 安全设计

### 5.1 路径与文件树边界

- `sourcePath` 必须为绝对路径和现有目录。
- 不跟随目录树中的符号链接或目录联接；发现后阻断。
- 不执行、导入、安装或改写待扫描源码。
- 扫描前后对有界目录树计算 SHA-256。
- 哈希输入包含相对路径、文件类型、文件大小和文件内容。
- 单文件、文件数量和总字节数设置上限，超限按失败关闭处理。

初始上限与现有上传边界保持一致：500 个文件、总计 50 MiB。单个文件默认不超过 15 MiB。

### 5.2 进程与环境边界

本阶段保持 Cisco 扫描器本地离线运行，并新增安装策略专用执行预算。后续 P1 将把通用 `ProcessRunner` 从“继承环境后删除少量密钥”改为环境变量白名单：

- 仅保留系统运行所需的最小变量。
- 强制 `HF_HUB_OFFLINE=1`、`TRANSFORMERS_OFFLINE=1`。
- 独立缓存和临时目录。
- `shell=False`，命令与参数分离。
- 扫描器内部超时小于 OpenClaw 外层超时。

M6 v1 建议内部预算 12 秒，OpenClaw 配置预算 15 秒。若当前机器性能不足，可先将外层预算调为 20 秒完成真实性验收，再单独优化性能；任何超时都不得默认放行。

### 5.3 失败关闭规则

| 失败场景 | 稳定规则编号 | 决策 |
|---|---|---|
| 请求不是合法 JSON 对象 | `AEGIS_POLICY_INVALID_REQUEST` | block |
| 协议版本不支持 | `AEGIS_POLICY_PROTOCOL_MISMATCH` | block |
| 目标类型暂不支持 | `AEGIS_POLICY_UNSUPPORTED_TARGET` | block |
| 路径无效或越界 | `AEGIS_POLICY_INVALID_SOURCE` | block |
| 文件树超限/含链接 | `AEGIS_POLICY_SOURCE_REJECTED` | block |
| 扫描超时 | `AEGIS_POLICY_SCAN_TIMEOUT` | block |
| 扫描器或策略异常 | `AEGIS_POLICY_SCAN_FAILED` | block |
| 扫描前后哈希变化 | `AEGIS_POLICY_SOURCE_CHANGED` | block |

适配器自身只有在无法生成任何协议响应的灾难性错误时才返回非零退出；普通可归类错误均输出合法 `block` JSON，便于操作员获得明确原因。OpenClaw 外层仍会对非零退出再次失败关闭。

## 6. 代码变更设计

| 路径 | 变更 | 目的 |
|---|---|---|
| `backend/openclaw_install_policy.py` | 新增协议模型、树哈希、Finding 映射和同步执行器 | 核心准入适配层 |
| `tools/openclaw_install_policy.py` | 新增稳定命令行入口 | 供 OpenClaw 以可信脚本方式调用 |
| `backend/tests/test_openclaw_install_policy.py` | 新增协议和故障关闭测试 | 防止失败放行与输出漂移 |
| `config/openclaw.install-policy.example.json5` | 新增配置示例 | 降低真实对接成本 |
| `docs/M6_OPENCLAW_INSTALL_POLICY_DESIGN.md` | 本设计文档 | 设计、边界和验收真值 |
| `artifacts/experiment/2026-08-26-openclaw-install-policy-v1/` | 运行计划、日志和结果 | 留存可复核证据 |

不修改以下冻结项：

- `config/admission_policy.yaml` 决策语义。
- Cisco/Aegis Finding 严重度。
- SkillTrustBench 全量结果。
- 600 条密封回归结果。
- 动态审计的“最终决策不变”约束。

## 7. 测试与验收

### 7.1 最小测试集

1. 合法安全 Skill：输出 `allow`。
2. 中/低风险 Finding：输出 `warn` 且理由非空。
3. 高/严重风险 Finding：输出 `block`。
4. UNKNOWN Finding：输出 `block`。
5. 非法 JSON：输出合法 `block`。
6. protocolVersion 非 1：输出 `block`。
7. `plugin` 目标在 v1：输出 `block`。
8. 相对路径、文件路径、不存在路径：输出 `block`。
9. 目录树含符号链接或超限：输出 `block`。
10. 扫描超时、扫描器异常、策略异常：输出 `block`。
11. 扫描期间源码变化：输出 `block`。
12. Finding 超长、超量或含绝对路径：输出仍符合 OpenClaw 限制。
13. CLI 标准输出可被单次 `json.loads` 解析。

### 7.2 端到端验收

最低验收：

- 内置安全 Skill 真实 Cisco + Aegis 扫描后返回 `allow`。
- 内置恶意外传 Skill 真实扫描后返回 `block`。
- 扫描器路径故意设为不可用时返回 `block`。
- 所有测试过程中输入目录哈希不变。

完整验收：

- 安装安全 Skill 成功。
- 安装危险 Skill 被阻止且无安装残留。
- REVIEW 流程需要明确确认，并在确认后重新扫描。
- 更新内容哈希变化时重新扫描。
- `openclaw doctor --deep` 通过。
- 温态扫描 P95 小于 10 秒；若未达标，必须如实记录，不影响失败关闭正确性。

## 8. 实施阶段

### M6-1：同步适配器

- 完成协议请求/响应模型。
- 完成 Skill 目录扫描、文件树哈希和决策映射。
- 完成 CLI 入口和配置示例。
- 完成专项单元测试与本地真实样本冒烟。

### M6-2：OpenClaw 真实安装闭环

- 在本机安装或连接 OpenClaw。
- 配置 `security.installPolicy`。
- 执行 allow/warn/block/故障四类安装验证。
- 验证阻断残留、警告确认和更新重扫。

### M6-3：隔离与审计证据

- 将扫描子进程环境改为白名单。
- 增加独立临时目录和资源上限。
- 落盘脱敏准入记录并接入现有查询界面。
- 记录来源、树哈希、规则/策略版本和耗时。

### M6-4：插件/MCP 安装包

- 识别插件包中的 Skill、MCP 配置和依赖清单。
- 聚合多扫描器 Finding。
- 建立小型插件/MCP 对接验证集。
- 明确“安装包静态审计”与“远程 MCP 运行监控”的能力边界。

## 9. 停止与降级条件

- 若同步扫描 P95 在预热后仍大于 10 秒，先保持失败关闭并拆分“快速同步扫描 + 可疑项深度复核”，不降低为超时放行。
- 若插件包结构适配在提交前无法稳定完成，冻结 Skill 完整闭环，把插件/MCP 标记为 Beta，不做全覆盖声明。
- 若必须执行第三方代码才能完成某项检查，该项退出安装同步链路，进入后续隔离动态复核。
- 若任何实现要求修改密封回归集或既有评价定义，停止实现并重新进行独立决策评审。

## 10. 完成定义

M6 v1 只有同时满足以下条件才可标记完成：

- OpenClaw protocol v1 输入输出严格有效。
- 安全、复核、阻断和失败关闭四条路径均有自动测试。
- 真实内置安全/恶意 Skill 的扫描结果符合预期。
- 扫描前后目录树身份一致。
- 关键链路不依赖 Web 服务、网络、大模型、GPU或 Docker。
- 文档、配置示例、运行证据和复现命令齐全。
- 局限性中明确写明 plugin/MCP 与动态审计尚未纳入 v1 主决策。

完成 M6 v1 后，系统可表述为：

> Aegis Chain 已形成面向 OpenClaw Skill 安装流程的本地、同步、失败关闭静态供应链准入原型，并保留可复核的规则与文件身份依据。
