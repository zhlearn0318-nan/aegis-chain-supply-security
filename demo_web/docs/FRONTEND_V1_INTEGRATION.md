# Aegis Chain 前端 v1 对接说明

> 完成日期：2026-08-10  
> 前端：React + Vite  
> API：`/api/v1`  
> 扫描 schema：`1.1`  
> 状态：已实现并验证

## 1. 本次完成内容

前端已从旧 `/api` 全量迁移到 `/api/v1`，并补齐统一平台接入最容易遗漏的三类状态：

- HTTP `202 Accepted` 只表示任务已进入队列，不表示扫描完成；
- `policy_trace` 说明策略版本、命中规则、原因和关联 Finding；
- API 失败按 `error.code` 处理，中文 `message` 只用于展示。

本次没有修改 Cisco 扫描器、结果归一化、YAML 阈值或 SQLite 编排。

## 2. 代码结构

| 文件 | 职责 |
|---|---|
| `frontend/src/api.js` | v1 基础路径、envelope 校验、结构化错误、上传、查询和导出 URL |
| `frontend/src/api.test.js` | 7 项无网络客户端契约测试 |
| `frontend/src/main.jsx` | 页面状态、退避轮询、策略证据和错误展示 |
| `frontend/src/styles.css` | ready/degraded/offline、策略证据、错误与可访问性样式 |

需要连接其他地址时设置：

```powershell
$env:VITE_API_BASE = "http://127.0.0.1:8000"
pnpm build
```

同源部署时不设置该变量，客户端直接请求当前域名下的 `/api/v1`。

## 3. 客户端契约

普通成功响应必须满足：

```json
{
  "api_version": "v1",
  "data": {}
}
```

若 HTTP 成功但响应不是上述结构，客户端生成：

```text
INVALID_API_ENVELOPE
```

这样可以阻止反向代理错误、旧接口响应或 React HTML 兜底被误当作扫描数据。

后端错误会保留：

```text
status + code + message + details
```

网络不可达使用客户端代码 `NETWORK_ERROR`；上传前缺文件使用 `INPUT_REQUIRED`。

## 4. 任务状态处理

| 状态 | 页面展示 | 前端动作 |
|---|---|---|
| `queued` | `HTTP 202 · ACCEPTED / 等待执行` | 继续轮询，不读取最终决策 |
| `running` | `SCANNING / 扫描中` | 继续轮询 |
| `completed` | `ALLOW/REVIEW/BLOCK/UNKNOWN` | 展示 Finding、策略证据和导出按钮 |
| `failed` | `UNKNOWN / 失败闭锁` | 展示失败原因，不自动放行 |

轮询使用 1、1、2、2、2、5 秒的本地退避序列，同一任务不会并发发出多个查询。除 `SCAN_NOT_FOUND` 外，暂时性查询失败仍会低频重试并显示错误码。

## 5. 策略证据展示

页面显示以下字段：

- `policy_id@policy_version`；
- `rule_id`；
- `reason`；
- `matched_severities`；
- `matched_finding_ids` 数量与前 8 个 ID；
- `fail_closed`。

健康区域同时显示当前加载的策略版本和失败闭锁开关，方便现场确认“扫描结果使用的是哪份策略”。

## 6. 验证结果

| 检查 | 结果 |
|---|---|
| 前端客户端测试 | `7 passed` |
| Vite 生产构建 | 16 modules，JS 213.37 kB，CSS 17.33 kB |
| 旧接口字符串 | 0 |
| 后端回归 | `58 passed` |
| 真实 v1 Skill 创建 | `202 / queued / PENDING_SCAN` |
| 真实终态 | `completed / BLOCK / 4 findings / 1 CRITICAL` |
| 命中策略 | `POLICY_BLOCK_SEVERITY / fail_closed=true` |
| JSON/Markdown 导出 | 均为 200 |

完整证据：`artifacts/experiment/2026-08-10-m1-3-frontend-v1/`。

## 7. 当前限制与下一步

- 页面目前没有登录、API Key/JWT 或租户信息；仅适合本机或受控局域网。
- 没有加入浏览器自动化依赖，本轮以客户端契约测试、生产构建和真实后端链路作为验收。
- 当前预置样本只用于工程回归，不能据此宣称检测准确率。
- 启动脚本会校验 `/api/v1/health`；若 8000 端口被旧服务占用，会明确提示先停止或迁移该服务，不会自动结束未知进程。

下一步进入 SkillTrustBench 来源与许可证审计，冻结 50–100 条试运行样本和标签，再编写批量评测器。
