# M5 P0/P1/P2 工程收敛执行计划

> 启动日期：2026-08-24  
> 执行分支：`dynamic-audit-v1`  
> 用户授权：完成 M5 全部 P0/P1/P2 工程项；里程碑验收后可直接提交并推送；允许引入固定版本、已核验许可与哈希的必要开源依赖；P0-5 必须使用真实 Windows VM，不可用本机目录、容器或异用户环境模拟替代。Windows Sandbox 原为首选，但当前家庭版宿主不提供该功能，因此允许具备硬件身份的 VirtualBox/VMware/QEMU/Hyper-V guest。

## 1. 统一真值与收敛原则

现有 Cisco/Aegis 确定性检测核心、Finding IR、四态准入、密封回归和受控动态 fixture 作为基线，不为了工程收敛再调规则。后续只建立一套任务、身份、证据、健康和发布真值，前端不自行推断后端没有证明的状态。

每个里程碑必须完成：预注册验收合同→最小实现→负面与真实运行→完整回归→证据与限制→独立 Git 提交与远端推送。

## 2. 总路线与退出门

| 阶段 | 当前状态 | 核心交付 | 退出门 |
| --- | --- | --- | --- |
| P0-1 可移植启动 | 已完成 | preflight、固定来源重建、换用户验证 | `3f02072`，后端 329/前端 10 |
| P0-2 动态任务控制 | 已完成 | 全局互斥、FIFO、有界队列、去重/冷却、重启恢复 | 335 后端 + 10 前端；全部专项门通过 |
| P0-3 状态真值 | 已完成 | `CURRENT_STATUS.md`、历史快照标记、文档契约测试 | 341 后端 + 10 前端；活动入口口径一致 |
| P0-4 自身供应链卫生 | 已完成 | 精确依赖、LICENSE/NOTICE、自身 SBOM、依赖/Secret/许可扫描 | 12/12 gate；共享环境与前端已知漏洞 0 |
| P0-5 发布门 | 程序完成、实机待验收 | 真实 Windows VM 从私有远端新克隆到四链 E2E | 真实洁净 VM 通过才允许候选版 |
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

## 7. P0-4 验收合同

- run id：`2026-08-24-project-supply-chain-hygiene-dev-v1`；等级 `auxiliary/dev`；基线 `08562f6`。
- 研究问题：仓库能否对自身直接/传递依赖、许可证、漏洞、秘密和发布制品形成可重复、失败闭锁的准入证据？
- 初始审计：Python 直接依赖未锁定 1；Node `latest` 4；根项目许可证/NOTICE 0；项目级发布 SBOM 0；Node High 漏洞 1（nanoid 3.3.16 / GHSA-2v37-7h3g-55p8）。
- 备择假设：所有直接依赖精确固定；Python lock 和 pnpm lock 带完整性哈希；根 LICENSE/第三方 NOTICE 明确；CycloneDX 项目 SBOM 可重复生成；Python/Node 已知漏洞 High/Critical=0；秘密扫描 verified leaks=0。
- 停止条件：需要删除或隐瞒真实漏洞、放宽已有安全门、提交扫描器二进制/令牌、执行第三方样本。
- 必需证据：修复前后 audit、锁文件哈希、SBOM、许可证清单、Secret 扫描、仓库自扫描、专项/全量回归。
- 边界：一次扫描为时间截面，不证明未来无新 CVE；许可证清单不是法律意见；私有比赛仓库默认不授予再分发权。

## 8. P0-4 实际结果与决策

- 初始前端锁包含 `nanoid 3.3.16` 的 1 个 High 通告；Cisco 旧共享锁的全量 OSV 审计得到 19 个受影响包、118 条数据库记录。后者包含同一漏洞的别名/重复记录，不能表述为 118 个独立 CVE。
- Web 后端 15 包、共享运行时 17 包安全覆盖和前端 4 个直接依赖均精确固定；Python 下载对象带 SHA-256，pnpm 锁内 50 个组件均有完整性值。
- 实际共享运行时共 126 个 Python 包，全部可映射至 Cisco 锁、Web 锁或安全覆盖锁；`pip check` 冲突 0，当日项目子集/共享环境/Node 已知漏洞均为 0。
- CycloneDX 1.6 项目 SBOM 覆盖 126 个 Python 与 Windows x64 已安装的 26 个 Node 组件，共 152 项；许可未知/越界 0。
- Secret 扫描检查 441 个文本文件，已验证泄露 0；合成占位值只按显式策略忽略，报告不保留原值。
- Cisco 兼容验收完成 Skill 固定集、MCP 内容 3 safe/3 unsafe、依赖漏洞 fixture 24 项 HIGH 和安全 fixture 0 项。发现并修复复现脚本把上游 pip-audit 空输出当 SAFE 的风险，现遇到内部错误或 oracle 不符均失败闭锁。
- 验收：自身供应链 gate 12/12、后端 `348 passed`、前端 `10 passed`、生产构建通过。结论为 `project_supply_chain_gate_supported_at_2026-08-25_snapshot`。
- 下一节点：P0-5 必须在真实 Windows VM 从私有远端新克隆开始验证，不以本机缓存、目录、Docker/WSL 或异用户模拟替代。

## 9. P0-5 验收程序实现状态

- 固定 `MinGit 2.53.0.windows.3`、`Node.js 24.15.0`、`Miniforge 25.11.0-1` 与 `pnpm 11.19.0`，所有下载安装对象记录官方来源、许可和 SHA-256/registry integrity。
- guest 控制器拒绝物理主机和目录模拟，核验私有远端 ref 等于预期 40 位提交，只向不存在的目标目录新克隆；引导前 preflight 必须因 Skill/MCP 运行时缺失而失败，防止复用宿主缓存。
- 发布门依次执行运行时重建、VM attestation 再验证、后端/前端完整回归、自身供应链门、真实服务启动、Skill/MCP/依赖上传、受控动态 fixture、任务列表/详情、7 份导出、停止和残留检查。
- 增加真实断网负面控制：为服务进程配置关闭的本机代理和全新 pip-audit 缓存，要求依赖任务形成 `failed / UNKNOWN / SCAN_EXECUTION_FAILED`，禁止离线时沿用成功结论。
- 修复 Skill 闭包假健康：健康接口现验证 Docker CLI、Linux 引擎和固定镜像；不可用时返回机器可读原因，闭包接口明确 503；基础动态 fixture 可独立运行。
- 本机非正式烟雾：四链 4/4、导出 7/7、断网失败闭锁通过，Docker 未启动时 503 降级通过；该结果只证明验收器可运行，不是 P0-5 真实 VM 证据。
- 工具链负面与完整性检查：官方 pnpm 11.19.0 tarball 的现场 SHA-512/SRI 一致且可执行；当前物理宿主被 VM 身份门拒绝，未发生下载或克隆。
- 回归：后端 `357 passed`，前端 `10 passed`，生产构建通过。
- 真实 guest 已安装 Windows 11 Enterprise Eval 25H2 ZH-CN x64 Build 26200.6584；Guest Additions、受保护 guestcontrol、无凭据代理和引导文件跨边界哈希核对均通过。
- 私有仓库认证已实现临时单仓库只读 Deploy Key 模式，强制严格主机密钥校验、禁交互、与 token 互斥，并在 clone 尝试结束后删除 guest 私钥；外部 Deploy Key 创建仍等待明确授权。
- 当前决策：`guest_ready_main_run_pending`。只有真实 VM 的完整 run 和制品哈希清单通过后，P0-5 才能标记完成。
