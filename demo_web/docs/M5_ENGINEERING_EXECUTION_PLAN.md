# M5 P0/P1/P2 工程收敛执行计划

> 启动日期：2026-08-24  
> 执行分支：`dynamic-audit-v1`  
> 用户授权：完成 M5 全部 P0/P1/P2 工程项；里程碑验收后可直接提交并推送；允许引入固定版本、已核验许可与哈希的必要开源依赖；P0-5 必须使用 Windows Sandbox，不可用本机目录模拟替代。

## 1. 统一真值与收敛原则

现有 Cisco/Aegis 确定性检测核心、Finding IR、四态准入、密封回归和受控动态 fixture 作为基线，不为了工程收敛再调规则。后续只建立一套任务、身份、证据、健康和发布真值，前端不自行推断后端没有证明的状态。

每个里程碑必须完成：预注册验收合同→最小实现→负面与真实运行→完整回归→证据与限制→独立 Git 提交与远端推送。

## 2. 总路线与退出门

| 阶段 | 当前状态 | 核心交付 | 退出门 |
| --- | --- | --- | --- |
| P0-1 可移植启动 | 已完成 | preflight、固定来源重建、换用户验证 | `3f02072`，后端 329/前端 10 |
| P0-2 动态任务控制 | 已完成 | 全局互斥、FIFO、有界队列、去重/冷却、重启恢复 | 335 后端 + 10 前端；全部专项门通过 |
| P0-3 状态真值 | 已完成 | `CURRENT_STATUS.md`、历史快照标记、文档契约测试 | 341 后端 + 10 前端；活动入口口径一致 |
| P0-4 自身供应链卫生 | 部分完成 | 精确依赖、LICENSE/NOTICE、自身 SBOM、依赖/Secret/许可扫描 | 来源和当日扫描可复核 |
| P0-5 发布门 | 未完成 | Windows Sandbox 从新克隆到四链 E2E | 真实洁净 VM 通过才允许候选版 |
| P1 受控试点能力 | 部分/未完成 | 静态 worker 隔离、MCP/动态独立集、生命周期、CI、能力健康 | 独立效果与运维证据齐全 |
| P2 生产化控制面 | 未完成 | 身份/RBAC/租户、持久队列与 DB、强沙箱、治理、完整准入、可观测性 | 本地生产形态集成验收，外部组织系统差异明确 |

## 3. P0-2 验收合同

- run id：`2026-08-24-dynamic-queue-recovery-dev-v1`；等级 `auxiliary/dev`。
- 基线：`3f02072`；检测规则、策略和 fixture 哈希只读。
- 研究问题：能否在保留现有 SQLite 与单机 API 的前提下，使动态任务获得可持久、可解释、失败闭锁的全局调度？
- 零假设：并发请求仍可同时运行，或重启后任务永久停留在 `queued/running`。
- 备择假设：数据库原子领取保证全局 `running<=1`；FIFO 位置可见；活动重复提交返回同一 ID；队列超限返回 429；重启将遗留 running 标记为可解释失败并重新调度 queued。
- 必需指标：`max_concurrent_running=1`、FIFO 违反 0、重复新建任务 0、超限拒绝 1、永久中间态 0、工作区/容器残留 0。
- 停止条件：需要放宽动态 fixture 白名单、网络/容器安全门或静态决策。
- 最强替代解释：单机 SQLite 调度通过不等于多实例生产队列；外部 worker/消息队列保留为 P2-2。

### 3.1 最小代码图

| 路径 | 变更 | 风险控制 |
| --- | --- | --- |
| `backend/dynamic_queue.py` | 单 worker 调度器，只调用数据库原子领取 | 不保存 token/任意命令 |
| `backend/app.py` | 入队事务、队列位置、冷却、恢复和生命周期 | 不改动真实 runner |
| `backend/models.py` | 增加队列/尝试/恢复的机器可读字段 | 兼容历史记录 |
| `backend/api_contract.py` | 429 与队列错误契约 | 不泄露服务端资源细节 |
| `frontend/src/main.jsx` | 展示排队原因、位置和去重结果 | 不自行推断位置 |
| `backend/tests/test_dynamic_queue.py` | 并发、FIFO、队满、去重、崩溃恢复 | 使用受控 worker，不执行第三方样本 |

## 4. 证据与分支策略

每轮证据位于 `demo_web/artifacts/experiment/<run_id>/`，至少包含 `run_manifest.json`、`metrics.json`、`summary.md`、`claim_validation.md`、日志指针和 SHA-256 清单。里程碑通过后在 `dynamic-audit-v1` 上独立提交并推送；失败实验不覆盖，改用新 run id。

## 5. P0-2 实际结果与决策

- SQLite `dynamic_audits` 作为持久队列真值；独立唤醒式调度线程只消费数据库原子认领的 FIFO 队首。
- `BEGIN IMMEDIATE` 同时检查全局 running 和更新队首，因此双线程同时认领仍只有一个任务进入 running。
- 活动同类提交和完成后 5 秒冷却提交返回原任务 ID；该事实只出现在本次响应，不污染持久任务状态。
- 等待队列默认最多 4 个，可通过 `AEGIS_DYNAMIC_QUEUE_MAX_PENDING` 在 0–32 范围调整；超限返回结构化 429。
- 启动时遗留 running 任务失败闭锁为 `DYNAMIC_AUDIT_INTERRUPTED_BY_RESTART`；queued 保留顺序并标明恢复事实。
- 执行器异常退出或未写终态时由调度器补写 `DYNAMIC_AUDIT_WORKER_DID_NOT_FINALIZE`，不存在静默永久 running。
- UI 展示后端返回的队列位置、运行状态和去重说明；按钮不再把单个页面的 current 状态误当成全局执行真值。
- 专项 `14 passed`，后端完整 `335 passed`，前端 `10 passed` 且生产构建通过；规则、策略和动态 fixture 未改动。
- 结论：`supported_on_single_host_sqlite_scheduler`。该结论不外推到多实例、高可用消息队列；后者保留为 P2-2。

## 6. P0-3 实际结果与决策

- 新增仓库根 `CURRENT_STATUS.md`，集中记录当前能力、最新验证、M5 完成度、生产 NO-GO 与不主张范围。
- 根 README、主系统 README、QUICKSTART 和 SECURITY 只保留摘要并显式委托给唯一状态真值。
- `START_HERE.md`、`REPRODUCTION_REPORT.md`、旧开发计划、对接说明和评委审查均标记为历史/审查快照；原实验结论不覆盖。
- 新增根 `docs/README.md` 与 `demo_web/docs/README.md`，规定当前契约和 M1–M4 历史证据的阅读优先级。
- API 文档同步动态队列、Skill closure 接口、429、去重/恢复字段和失败闭锁语义。
- 新增 6 项文档契约测试，防止活动入口重新出现旧总数、个人路径或缺失状态链接。
- 验收：文档专项 `6 passed`，后端完整 `341 passed`，前端 `10 passed`，生产构建通过。
- 结论：`single_current_status_truth_enforced`；下一节点为 P0-4 项目自身供应链卫生。
