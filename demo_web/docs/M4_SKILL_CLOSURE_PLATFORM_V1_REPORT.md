# M4：Skill 运行时闭包平台接入 v1 报告

## 1. 结论

D3-D 已完成。D3-C 的 Skill 运行时目录闭包现在可以从统一平台的管理员动态验证页面手动触发，并通过既有任务系统完成后台运行、SQLite 脱敏持久化、轮询查询与页面展示。

真实验收不是直接调用底层函数，而是完整经过：

`管理员 HTTP API → 后台任务 → 固定 Docker fixture → Cisco + Aegis 静态复审 → SQLite → 任务详情 → 前端渲染`

验收结果为 completed。D3-C 的 59/59 接受门、3/3/3 文件闭包指标、2 条运行时风险和 2 次 Cisco 扫描全部保持不变；响应原文、数据库原文、管理员令牌、任务工作区、容器残留和最终决策变化均为 0。

## 2. 平台新增能力

### 2.1 管理员固定触发端点

新增端点：

```text
POST /api/v1/admin/dynamic-audits/skill-closure
```

调用要求：

- 必须通过 `X-Aegis-Admin-Token` 请求头提供管理员令牌；
- 请求体必须为空；
- 不接受 Skill 上传、文件路径、运行命令或自定义参数；
- 服务端只运行仓库中固定且哈希锁定的 Skill fixture。

缺失令牌和错误令牌均返回 401；携带任何请求体返回 400；合法任务以 202 接受。

### 2.2 统一动态任务模型

原有基础机制验证与新的 Skill 闭包共用 `dynamic_audits` 表，通过 `audit_type` 区分：

- `mechanism_fixture`：原有进程、文件、回环网络机制验证；
- `skill_runtime_closure`：Docker 目录闭包与 Cisco + Aegis 静态复审。

旧任务字段保留默认值，不需要数据库迁移。新任务使用固定身份 `aegis-skill-runtime-closure-v1`，安全边界明确记录：网络为 none、原始值不保留、策略影响为 none、决策变化为 0。

### 2.3 二次脱敏持久化

D3-C 后端已经不保留生成内容原文。平台 worker 在写入 SQLite 前又执行一次字段白名单，只允许持久化：

- 运行前后文件的路径、字节数、类别与 SHA-256；
- 新增、修改、删除路径列表；
- 静态扫描数量、Cisco 扫描次数与策略建议；
- 运行时风险的规则、分析器、严重度、相对路径、行号和证据哈希；
- 原文保留状态与泄漏计数。

即使底层结果意外携带 `materialized_bundle`、描述文本或其他额外字段，平台白名单也不会将其写入数据库。

### 2.4 页面展示

管理员动态验证区域现在提供两个固定按钮：

1. 基础机制：运行原有 3 个可信样本；
2. Skill 闭包：运行 Docker 隔离、目录差分和静态复审。

选择 Skill 闭包后，页面展示：

- 新增文件数量与闭包覆盖率；
- 运行时风险数量与决策变化；
- 新增文件路径、类别和缩略哈希；
- 新增风险的严重度、规则编号、文件和行号；
- 静态发现由运行前到运行后的变化，以及 Cisco 扫描次数；
- `POLICY EFFECT = NONE` 与不保留原文的边界提示。

## 3. 真实验收结果

| 指标 | 结果 |
|---|---:|
| 缺失令牌 / 错误令牌 | 401 / 401 |
| 带请求体调用 | 400 |
| 创建 / 详情 / 列表 | 202 / 200 / 200 |
| 闭包引擎健康状态 | ready |
| 任务状态 | completed |
| D3-C 接受门 | 59/59 |
| 新增 / 提升 / 哈希验证 | 3/3/3 |
| 运行时风险 | 2 |
| Cisco 扫描次数 | 2 |
| 前端 API 测试 | 10 passed |
| 前端生产构建 | passed |
| 完整后端回归 | 324 passed |

负面指标全部为 0：响应原文泄漏、数据库原文泄漏、管理员令牌泄漏、任务工作区残留、容器残留、第三方样本执行、互联网使用、镜像拉取和最终决策变化。

## 4. 首次运行异常及修复

第一次端到端验收中，真实 API 任务已经执行，但验收脚本读取 SQLite 后只退出事务上下文，没有显式关闭连接。Windows 因数据库文件仍被占用而拒绝删除临时目录，验收脚本因此失败。

修复方法是使用 `closing(sqlite3.connect(...))` 显式关闭连接，然后按完全相同的 API、fixture、指标和安全合同重跑。第二次运行成功，未通过修改指标或放宽安全配置规避问题。

## 5. 演示方式

1. 服务端配置长度不少于 16 位的 `AEGIS_ADMIN_TOKEN`；
2. 启动平台后进入“管理员动态验证”；
3. 在页面会话中输入令牌，点击“验证并加载历史”；
4. 点击“Skill 闭包”；
5. 等待页面轮询完成，查看新增文件与静态复审风险；
6. 强调页面中的 `DECISION Δ = 0`：本阶段提供补充证据，暂不自动改变最终准入结论。

令牌只保存在当前 React 内存中，不进入 URL、请求体、localStorage、sessionStorage、数据库或任务记录。

## 6. 证据位置

- `demo_web/artifacts/experiment/2026-08-23-skill-closure-platform-dev-v1/api_acceptance_evidence.json`
- `demo_web/artifacts/experiment/2026-08-23-skill-closure-platform-dev-v1/metrics.json`
- `demo_web/artifacts/experiment/2026-08-23-skill-closure-platform-dev-v1/run_manifest.json`
- `demo_web/artifacts/experiment/2026-08-23-skill-closure-platform-dev-v1/claim_validation.md`

## 7. 边界与下一步

当前平台仍不接受第三方 Skill 动态执行。它证明的是“固定自建 fixture 的闭包机制已进入可演示平台”，不是通用恶意代码沙箱。

下一步优先增加管理员动态任务的并发互斥和资源队列。当前单任务运行已经可靠，但现场连续点击或多个管理员请求可能同时占用 Docker、Cisco Scanner、CPU 和内存。加入全局单任务锁、排队状态和资源上限后，平台的演示稳定性会更强。
