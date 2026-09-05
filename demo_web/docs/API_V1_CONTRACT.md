# Aegis Chain API v1 对接契约

> 应用版本：`1.3.0`
> API 版本：`v1`
> 扫描结果 schema：`1.3`
> 默认策略：`aegis-chain-local-default@1.1.0`
> 更新日期：2026-08-31
> 状态：已实现、已测试、Skill 证据感知准入已启用

## 1. 使用原则

统一平台的新接入和当前网页均使用 `/api/v1`。旧脚本仍可继续使用 `/api`，两组接口共享同一个扫描任务、策略、适配器和 SQLite 数据库，不是两套扫描实现。网页参考实现见 `docs/FRONTEND_V1_INTEGRATION.md`。

兼容规则：

- `/api/v1` 的成功响应使用统一 envelope；
- `/api/v1` 的错误响应使用机器可读错误码；
- 创建扫描任务返回 HTTP `202 Accepted`；
- 查询接口保持异步轮询；
- 下载导出接口直接返回文件，不套成功 envelope；
- 未来 v1 可以增加可选字段，调用方必须忽略未知字段；
- 删除字段、改变字段含义或改变核心状态语义时必须升级到新 API 主版本。

## 2. 基础地址与文档

本地默认地址：

```text
http://127.0.0.1:8000
```

常用入口：

| 地址 | 用途 |
|---|---|
| `/api/v1/health` | v1 健康检查 |
| `/docs` | Swagger UI |
| `/openapi.json` | OpenAPI 3.1 契约 |

静态扫描接口当前仍用于本机演示且未启用认证。管理员动态验证接口已使用独立本地令牌鉴权；令牌来自服务端环境变量 `AEGIS_ADMIN_TOKEN`，请求头固定为 `X-Aegis-Admin-Token`。正式接入统一平台时仍建议由平台网关替换为统一身份认证与审计。

## 3. 成功与错误格式

### 3.1 普通成功响应

```json
{
  "api_version": "v1",
  "data": {
    "endpoint_specific": "typed payload"
  }
}
```

扫描任务位于 `data` 中，其自身包含 `schema_version: "1.3"`。依赖任务以及带 `requirements` 的 MCP 任务还可包含可选 `sbom`。

### 3.2 错误响应

```json
{
  "api_version": "v1",
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "扫描任务不存在",
    "details": null
  }
}
```

调用方应根据 `error.code` 处理流程，`message` 用于展示，不应解析中文文本判断错误类型。

### 3.3 导出响应例外

`/api/v1/scans/{job_id}/export` 成功时直接下载 JSON、Markdown 或 CycloneDX SBOM 文件，因此不使用成功 envelope。导出失败仍使用 v1 错误格式。

## 4. 接口清单

| 方法 | 路径 | 成功状态 | 成功数据 |
|---|---|---:|---|
| GET | `/api/v1/health` | 200 | 服务、策略和扫描器状态 |
| GET | `/api/v1/presets` | 200 | 预置样例列表 |
| POST | `/api/v1/scans/preset/{preset_id}` | 202 | 初始 `ScanJob` |
| POST | `/api/v1/scans/skill` | 202 | 初始 `ScanJob` |
| POST | `/api/v1/scans/mcp` | 202 | 初始 `ScanJob` |
| POST | `/api/v1/scans/dependency` | 202 | 初始 `ScanJob` |
| GET | `/api/v1/scans?limit=20` | 200 | 最近任务列表 |
| GET | `/api/v1/scans/{job_id}` | 200 | 单个任务状态与结果 |
| GET | `/api/v1/scans/{job_id}/export?format=json|md|sbom` | 200 | 下载扫描结果、报告或 CycloneDX 清单 |
| POST | `/api/v1/admin/dynamic-audits` | 202 | 初始 `DynamicAuditJob` |
| POST | `/api/v1/admin/dynamic-audits/skill-closure` | 202 | 初始 Skill 闭包 `DynamicAuditJob` |
| GET | `/api/v1/admin/dynamic-audits?limit=20` | 200 | 最近动态验证任务 |
| GET | `/api/v1/admin/dynamic-audits/{job_id}` | 200 | 动态验证状态与脱敏证据 |

### 4.1 能力级健康状态

`GET /api/v1/health` 的 `engines` 是能力状态，不是单一进程存活标志。每项至少包含 `ready`；不可用时还可包含 `reason_code` 和 `message`，供平台展示真实降级原因。客户端不得仅依据 HTTP 200 推断所有扫描能力可用。

Skill 闭包动态审计的 ready 会实际检查 Docker CLI、Linux 容器引擎、固定镜像身份、runner 配置和哈希锁定 fixture。任一条件不满足时，健康接口将该能力标为不可用；调用 `/api/v1/admin/dynamic-audits/skill-closure` 返回 `503 / DYNAMIC_AUDIT_NOT_READY` 及相同原因。机制动态 fixture 是独立能力，允许在 Docker 闭包降级时继续运行，二者不可互相代替。

`limit` 的最小值为 1，最大值为 100，默认值为 20。超出范围返回 `422 / REQUEST_VALIDATION_ERROR`，不再静默截断。

### 管理员动态验证边界

启动服务前，在当前 PowerShell 会话设置至少 16 位令牌：

```powershell
$env:AEGIS_ADMIN_TOKEN = "请替换为本次会话的随机令牌"
```

创建任务：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/admin/dynamic-audits" `
  -H "X-Aegis-Admin-Token: $env:AEGIS_ADMIN_TOKEN"
```

该 POST 必须为空请求体。任何 JSON、表单或自定义参数都会返回 `400 / DYNAMIC_AUDIT_BODY_NOT_ALLOWED`。调用方不能指定 fixture、文件路径、脚本、命令、环境变量或网络地址；服务端只运行 `aegis-safe-dynamic-fixtures-v1`。

查询时使用相同请求头。令牌不应写入 URL、请求体、日志、SQLite、浏览器持久化存储或汇报材料。

动态任务由 SQLite 持久 FIFO 统一调度，同一主机最多一个任务处于 `running`。默认允许 4 个等待任务，可用 `AEGIS_DYNAMIC_QUEUE_MAX_PENDING` 调整为 0–32；队列满时返回 `429 / DYNAMIC_AUDIT_QUEUE_FULL`。活动同类任务及完成后默认 5 秒冷却窗口内的同类请求返回原任务 ID，不创建新记录。

P0-2 新增字段：

| 字段 | 含义 |
| --- | --- |
| `submission_key` | 固定审计类型与 fixture 哈希形成的去重键 |
| `queue_position` | queued 时的实时 FIFO 位置；其他状态为 `null` |
| `queue_reason` | queued 的机器可读等待原因 |
| `deduplicated` / `dedupe_reason` | 本次创建响应是否合并到活动任务或冷却任务；该响应事实不写回原任务 |
| `attempt` / `started_at` / `finished_at` | 执行次数和最近一次起止时间 |
| `recovered_after_restart` / `recovery_count` / `recovery_note` | 服务重启恢复事实 |

启动恢复时，遗留 `running` 会以 `DYNAMIC_AUDIT_INTERRUPTED_BY_RESTART` 失败闭锁；queued 保持顺序继续等待。执行器返回但没有写入终态时，调度器写入 `DYNAMIC_AUDIT_WORKER_DID_NOT_FINALIZE`，调用方不得把这两种失败解释为安全。

## 5. 创建扫描任务

### 5.1 Skill ZIP

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/scans/skill" `
  -F "file=@C:\samples\example-skill.zip"
```

约束：

- 字段名为 `file`；
- 文件扩展名必须为 `.zip`；
- 最大 15 MB；
- 包内必须且只能有一个 `SKILL.md`；
- 最多 500 个 ZIP 成员；
- 服务检查目录穿越和单成员大小。

### 5.2 MCP JSON

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/scans/mcp" `
  -F "mcp_json=@C:\samples\mcp.json" `
  -F "requirements=@C:\samples\requirements.txt"
```

`requirements` 可省略。MCP JSON 顶层支持 `tools`、`prompts`、`resources` 或 `contents`。

### 5.3 Python 依赖

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/scans/dependency" `
  -F "requirements=@C:\samples\requirements.txt"
```

### 5.4 创建响应

```json
{
  "api_version": "v1",
  "data": {
    "schema_version": "1.3",
    "id": "b5ef8d0bb2d14d3a9144c8c0082bfbf8",
    "status": "queued",
    "target_kind": "skill",
    "source_kind": "preset",
    "display_name": "数据外传 Skill",
    "decision": "UNKNOWN",
    "policy_trace": {
      "policy_id": "aegis-chain-local-default",
      "policy_version": "1.1.0",
      "rule_id": "PENDING_SCAN",
      "reason": "扫描尚未完成，暂未执行准入策略。",
      "matched_severities": [],
      "matched_finding_ids": [],
      "fail_closed": true
    }
  }
}
```

示例省略了部分字段。创建时 `decision=UNKNOWN` 只表示任务尚未完成，不代表扫描失败。

### 5.5 依赖 SBOM

依赖扫描完成后，可直接下载 CycloneDX 1.5 JSON：

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/scans/{job_id}/export?format=sbom" -o result.cdx.json
```

SBOM 范围是 requirements 中的声明安装集合。静态分析不运行 resolver，不推断直接/传递角色，并写明 `transitive-graph-completeness=not-proven`。对不含 requirements 的任务请求 `sbom` 返回 `400 / SBOM_UNAVAILABLE`。

### 5.6 Finding 证据字段

schema `1.3` 为每条 Finding 增加四个证据维度：

| 字段 | 可选值 | 含义 |
|---|---|---|
| `evidence_confidence` | `POTENTIAL`、`CORROBORATED`、`CONFIRMED` | 当前证据对风险事实的证明程度 |
| `reachability` | `REACHABLE`、`REFERENCED`、`EXAMPLE`、`TEST`、`UNKNOWN` | 风险位置与真实运行入口的关系 |
| `behavior_alignment` | `DECLARED`、`UNDECLARED`、`CONTRADICTORY`、`UNKNOWN` | 实现行为与 Skill 声明是否一致 |
| `evidence_source` | `CISCO`、`AEGIS_STATIC`、`AEGIS_SEMANTIC`、`AEGIS_DYNAMIC`、`CUSTOM`、`DEPENDENCY`、`UNKNOWN` | 证据来源 |

默认策略不会因为新增字段而全面放松故障关闭。只有正规 Cisco Skill 归一化产生、同时属于策略配置的“上下文相关原语规则”的 `HIGH + POTENTIAL + CISCO` finding 可以进入 `POLICY_REVIEW_UNCORROBORATED_CISCO_HIGH`。完整执行链、未列入候选清单的 Cisco HIGH、CRITICAL、非 Cisco HIGH、UNKNOWN 和扫描失败仍不自动放行。

## 6. 查询与轮询

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/scans/{job_id}"
```

处理规则：

| `status` | 动作 |
|---|---|
| `queued` | 等待并继续轮询 |
| `running` | 等待并继续轮询 |
| `completed` | 读取 `decision` 和 `findings` |
| `failed` | 按 `UNKNOWN` 处理，不自动放行 |

建议在第 1、2、4、6、8 秒轮询，之后以较低频率继续。平台自身超时后可以停止前端等待，但不得把未完成任务标记为安全。

## 7. 错误码

| HTTP | 错误码 | 含义 | 建议动作 |
|---:|---|---|---|
| 404 | `API_ROUTE_NOT_FOUND` | v1 路径不存在 | 检查路径和 API 版本 |
| 405 | `METHOD_NOT_ALLOWED` | 请求方法错误 | 使用接口清单规定的方法 |
| 404 | `PRESET_NOT_FOUND` | 预置样例不存在 | 检查 preset ID |
| 400 | `SKILL_FILE_TYPE_INVALID` | Skill 不是 ZIP | 修改上传文件 |
| 400 | `SKILL_ARCHIVE_INVALID` | ZIP 结构或路径不安全 | 修复压缩包 |
| 400 | `MCP_FILE_TYPE_INVALID` | MCP 文件不是 JSON | 修改上传文件 |
| 400 | `MCP_PAYLOAD_INVALID` | MCP JSON 无法解析或无对象 | 修复 JSON 内容 |
| 413 | `UPLOAD_TOO_LARGE` | 文件超过 15 MB | 减小文件或协调调整限制 |
| 404 | `SCAN_NOT_FOUND` | 任务不存在 | 检查 job ID 与数据保留状态 |
| 503 | `ADMIN_TOKEN_NOT_CONFIGURED` | 服务端未安全配置管理员令牌 | 设置环境变量后重启服务 |
| 401 | `ADMIN_TOKEN_INVALID` | 管理员令牌缺失或不匹配 | 重新输入本次会话令牌 |
| 400 | `DYNAMIC_AUDIT_BODY_NOT_ALLOWED` | 动态创建请求包含请求体 | 删除全部自定义参数和请求体 |
| 429 | `DYNAMIC_AUDIT_QUEUE_FULL` | 动态等待队列达到配置上限 | 等待当前任务结束后重试；不要绕过队列并发执行 |
| 503 | `DYNAMIC_AUDIT_NOT_READY` | 固定 fixture 配置不可用 | 检查本地安装完整性，不要改为用户路径 |
| 404 | `DYNAMIC_AUDIT_NOT_FOUND` | 动态验证任务不存在 | 检查任务 ID 与数据保留状态 |
| 400 | `EXPORT_FORMAT_UNSUPPORTED` | 导出格式不是 JSON/Markdown/SBOM | 改用 `json`、`md` 或 `sbom` |
| 400 | `SBOM_UNAVAILABLE` | 当前任务没有依赖清单 | 选择依赖任务或带 requirements 的 MCP 任务 |
| 422 | `REQUEST_VALIDATION_ERROR` | 缺字段、类型或范围错误 | 按 `details` 修正请求 |
| 500 | `INTERNAL_SERVER_ERROR` | 未捕获的网关内部错误 | 不放行，记录并通知管理员 |
| 其他 | `HTTP_ERROR` | 其他 HTTP 错误 | 记录状态码、错误码和上下文 |

未知 API 路径会返回 JSON 404，不会再落入 React 页面并产生 HTML 200。

## 8. 旧接口迁移

| 行为 | `/api` | `/api/v1` |
|---|---|---|
| 普通成功体 | 直接返回数据 | `{api_version, data}` |
| 已知错误体 | `{detail}` | `{api_version, error}` |
| 创建任务状态 | 200 | 202 |
| 查询任务 | 直接 `ScanJob` | `data` 中的 `ScanJob` |
| 导出文件 | 直接下载 | 直接下载 |
| 扫描任务和数据库 | 共享 | 共享 |

迁移步骤：

1. 将基础路径改为 `/api/v1`；
2. 创建和查询响应从 `body` 改为读取 `body.data`；
3. 接受创建状态码 202；
4. 错误处理改为读取 `body.error.code`；
5. 保持对 ScanJob schema `1.3` 的解析，并允许 `sbom=null`；
6. 忽略未来新增的可选字段。

## 9. 当前安全边界

- 静态扫描接口未启用认证；管理员动态验证只有本地令牌鉴权，尚无 TLS、限流和租户隔离；
- 只适合本机或受控局域网演示，不应直接暴露到公网；
- API 成功只代表请求或扫描流程成功，不代表组件绝对安全；
- `UNKNOWN` 和 `failed` 必须默认不放行；
- 动态模块只验证自建哈希锁定 fixture；它不是不可信代码沙箱，禁止执行第三方 Skill。

## 10. 验证证据

- 当前自动化测试与真实冻结结果见 `M3_STATIC_AUDIT_COMPLETION_REPORT.md`；
- OpenAPI：18 个业务路径，9 个旧接口、9 个 v1 接口，0 个重复 operation ID；
- 旧 Skill 与 v1 Skill 的哈希、决策、Finding 数量和策略规则完全一致；
- v1 Skill、MCP、依赖创建均返回 202，并完成真实扫描；
- 未知 v1 路径真实返回 `404 / API_ROUTE_NOT_FOUND`。

完整证据位于 `artifacts/experiment/2026-08-10-m1-3-api-v1-contract/`。
