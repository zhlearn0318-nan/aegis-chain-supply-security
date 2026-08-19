# M3 管理员动态验证 API 与页面实现报告

> 阶段：M3 第六批  
> 完成日期：2026-08-18  
> 接受运行：`2026-08-18-admin-dynamic-api-ui-dev-v1`  
> 基线：`2026-08-18-safe-dynamic-fixture-dev-v2`  
> 结论：已完成管理员专用异步接入；仍为可信 fixture 机制自检，不是不可信代码沙箱

## 1. 本阶段完成了什么

上一阶段已经证明三份自建、SHA-256 锁定的 Python fixture 能稳定产生进程、stdin、环境变量、文件和回环网络事件。本阶段把该能力接入 Aegis Chain 本机平台，形成可以现场演示的管理员页面和 API：

- 新增独立的 `DynamicAuditJob` 数据契约和 SQLite 历史表；
- 新增管理员创建、历史、详情三条 `/api/v1` 接口；
- 使用 `AEGIS_ADMIN_TOKEN` 环境变量和 `X-Aegis-Admin-Token` 请求头鉴权；
- 新增异步后台执行、页面轮询、逐 fixture 状态和 INFO 事件展示；
- 动态工作区执行完自动删除，只保存脱敏机制证据；
- 前端令牌只保存在 React 内存中，刷新或点击“清除会话”后消失；
- 完整保留“INFO-only、policy effect 为 none、决策变化为 0”的边界。

## 2. 为什么单独建立管理员接口

现有 Skill/MCP 上传接口处理的是静态制品。如果动态模块直接复用上传路径，就会形成“用户上传代码—服务器执行”的高风险入口，而当前电脑没有 Docker、虚拟机、云沙箱、独立出口代理和可回滚系统镜像，不能支撑不可信代码执行。

因此，本阶段的动态接口不是“扫描任意 Skill”，而是“管理员触发平台内置机制自检”。它只证明动态观测链路当前可用，可以作为现场技术演示与运行时自检证据，不能证明第三方 Skill 安全。

## 3. 安全边界

### 3.1 身份验证

- 服务端只从进程环境变量 `AEGIS_ADMIN_TOKEN` 读取令牌；
- 令牌少于 16 位或未配置时，接口返回 `503 / ADMIN_TOKEN_NOT_CONFIGURED`；
- 请求缺少令牌或令牌不匹配时，返回 `401 / ADMIN_TOKEN_INVALID`；
- 使用常量时间比较，错误响应不回显输入值；
- 令牌不写入源码、SQLite、响应、任务记录或服务日志。

该令牌鉴权适合本机比赛演示，不等同于政企生产身份体系。接入统一平台时应由网关的 SSO、JWT/mTLS、RBAC、租户隔离和审计策略替代。

### 3.2 执行入口

创建接口固定为：

```text
POST /api/v1/admin/dynamic-audits
```

该请求必须为空。只要包含 JSON、表单或其他请求体，就返回 `400 / DYNAMIC_AUDIT_BODY_NOT_ALLOWED`。接口没有以下参数：

- 没有脚本上传；
- 没有文件路径；
- 没有 fixture 选择；
- 没有命令或参数；
- 没有自定义环境变量；
- 没有网络地址。

服务端唯一可执行配置是仓库内的 `config/safe_dynamic_fixtures.json`，其中 fixture 根目录、脚本哈希、超时、允许的 Python 子命令哈希和回环端口策略均被固定。

### 3.3 证据与决策

动态任务没有 `ALLOW / REVIEW / BLOCK` 字段。其 `completed` 只表示内置 fixture 的预期机制全部被观测，不代表任何业务 Skill 已通过准入。

所有展示事件都满足：

- `severity = INFO`；
- `policy_effect = none`；
- `decision_changes = 0`；
- 不保留 stdin、环境变量、网络载荷、stdout 或 stderr 原文；
- 不返回服务器上的 fixture 绝对路径。

## 4. API 契约

| 方法 | 路径 | 成功状态 | 作用 |
|---|---|---:|---|
| POST | `/api/v1/admin/dynamic-audits` | 202 | 创建固定样本验证任务 |
| GET | `/api/v1/admin/dynamic-audits?limit=20` | 200 | 查询管理员动态任务历史 |
| GET | `/api/v1/admin/dynamic-audits/{job_id}` | 200 | 查询状态、指标和脱敏证据 |

三条接口都要求 `X-Aegis-Admin-Token`。成功响应继续使用统一 `{api_version, data}` envelope；错误响应使用稳定错误码。

动态任务状态为：

- `queued`：已接受，等待后台执行；
- `running`：固定 fixture 集正在运行；
- `completed`：执行完成且全部预期机制通过；
- `failed`：运行异常或机制检查不完整。

## 5. 前端页面

页面新增“管理员动态验证”区域，分成四个部分：

1. 管理员令牌输入与会话清除；
2. 固定 fixture 边界说明和启动按钮；
3. 3/3、7/7、策略违规、决策变化等核心指标；
4. 逐 fixture 状态、INFO 事件和管理员历史。

令牌使用 React `useState` 保存，没有调用 `localStorage` 或 `sessionStorage`。请求只在专用 Header 中携带令牌，不进入 URL 或请求体。页面刷新后需要重新输入，这是刻意的数据最小化设计。

## 6. 最终验证结果

独立验证文件：`artifacts/experiment/2026-08-18-admin-dynamic-api-ui-dev-v1/integration_verification.json`。

### 6.1 API 与边界

| 检查 | 结果 |
|---|---:|
| 创建任务 | HTTP 202 |
| 查询详情 | HTTP 200 |
| 查询历史 | HTTP 200 |
| 携带自定义请求体 | HTTP 400，稳定错误码 |
| 令牌出现在响应 | 0 |
| 令牌出现在 SQLite payload | 0 |
| fixture 绝对路径暴露 | 0 |
| 任务工作区残留 | 0 |
| 前端持久化存储 API 调用 | 0 |

### 6.2 动态机制

| 指标 | 结果 |
|---|---:|
| fixture 完成 | 3/3 |
| 预期机制通过 | 7/7 |
| 进程 / stdin / 环境事件 | 1 / 1 / 3 |
| 文件读 / 文件写 | 1 / 1 |
| 回环连接 | 1 |
| 策略违规 | 0 |
| 超时 | 0 |
| 事件解析错误 | 0 |
| 非 INFO 证据 | 0 |
| 原始测试值泄露 | 0 |
| 第三方/受保护样本读取或执行 | 0 / 0 |
| 互联网连接允许 | 0 |
| 准入决策变化 | 0 |

本轮接口路径下三份 fixture 总执行时间为 580 ms，平均 193.33 ms，最大 225 ms。该耗时只代表极小的自建机制 fixture，不能与约 4 秒的 Cisco 完整静态扫描直接比较。

### 6.3 回归

- 后端完整测试：`142 passed`；
- 前端 API 测试：`9 passed`；
- Vite 生产构建：通过；
- OpenAPI 已声明 202、400、401、503 以及管理员 Header；
- 现有静态扫描、Cisco 适配、Aegis Context 和准入策略测试全部保持通过。

## 7. 保留的失败轮次

本阶段没有删除或覆盖失败证据：

1. 首轮测试使用系统临时目录，遇到 Windows 权限拒绝；改为把 pytest 临时目录固定到本阶段 artifact 目录。
2. 独立验证器前两轮发现 SQLite 文件句柄在 Windows 上未可靠释放；随后把后端所有数据库访问改为显式关闭连接，解决真实资源清理问题。
3. 一轮持久化检查把页面说明文字中的 `localStorage/sessionStorage` 误判成 API 调用；保留该失败结果，并把检查收紧为真实调用语法。

这些失败没有改变动态机制结果，但暴露并修复了测试可复现性、数据库资源释放和验证器假阳性问题。

## 8. 本机使用方法

在 PowerShell 当前会话设置临时令牌，然后启动：

```powershell
$env:AEGIS_ADMIN_TOKEN = "请替换为至少16位的随机令牌"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1"
```

打开 `http://127.0.0.1:8000`，进入“管理员动态验证”，输入同一令牌后加载历史或启动验证。令牌不要写入源码、文档、截图或汇报稿。

## 9. 当前局限与后续建议

当前尚未实现：

- 不可信第三方 Skill 动态执行；
- Docker/虚拟机级隔离、只读根文件系统和快照回滚；
- 出口代理、DNS 控制、TLS 流量元数据和外部服务仿真；
- 平台级 SSO/RBAC、限流、租户隔离和管理员操作审计；
- 动态证据与具体静态扫描任务的关联。

下一阶段建议先增强管理员执行面的并发限制、非敏感操作审计和统一平台对接字段；在具备 Docker/虚拟机或远程沙箱前，不扩大到第三方样本执行。600 条回归集继续封存，不因本次 UI/API 集成而打开。
