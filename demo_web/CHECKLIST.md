# SkillTrustBench 官方 10% 子集复核检查表

## 数据准备

- [x] 用户确认使用官方固定 10% 子集（556 条）。
- [x] 锁定官方结果仓库提交与子集文件 SHA-256。
- [x] 核对 556 条唯一 ID 与 166/105/285 标签分布。
- [x] 子集与完整 ground truth 逐条一致。
- [x] 556 个 case 均存在于已审计完整压缩包。
- [x] 官方榜单 ID 哈希与当前文件按协议复算结果一致。
- [x] 安全导入 556 条，只读化并生成逐 case tree hash manifest；553 条可读，3 条被 Defender 阻断。

## 评测工程

- [x] 新增 `official10` 模式和固定输入校验。
- [x] 参数化样本根目录安全检查。
- [x] 新增统一策略层 loose non-normal 二分类指标。
- [x] 新增断点续扫及恢复前缀复核。
- [x] 补充数据导入、指标和续扫单元测试。
- [x] 全量后端测试通过：`70 passed`。

## 556 条扫描

- [x] 精确命令和运行 manifest 落盘。
- [x] 556/556 均产生 completed 或 failed/UNKNOWN 终态：546 completed、10 abstain。
- [x] 553 条可读样本扫描前后 tree hash 一致；3 条隔离样本保留固定归档身份。
- [x] 只出现冻结允许的本地静态分析器。
- [x] 输出三分类指标、补充二分类指标和 T01–T09 切片。
- [x] 输出 FP、恶意 FN 和全部分类错误清单。

## 汇报与交接

- [x] 生成官方 556 条扫描结果 Markdown 报告。
- [x] 对照 90 条基线并明确不可直接比较的分布差异。
- [x] 区分本系统策略指标与官方 Cisco `actual_safe` 榜单指标。
- [x] 更新 WORK_LOG、DEVELOPMENT_PLAN、README 和对接文档。
- [x] 给出下一轮误报/漏报分析与动态审计开发优先级。

## 全量 5,520 条追加复核

- [x] 固定完整 ground truth、ZIP 与 5,520 条 ID 的 SHA-256。
- [x] 安全导入全量只读案例；记录 61 条端点防护阻断和 8 条 Windows 路径不兼容，不绕过防护、不改写样本。
- [x] 增加 `full` 模式、1—8 路有界并发和并发参数冻结。
- [x] 5 条顺序/四路并发对照判定完全一致。
- [x] 全量 5,520/5,520 产生终态：5,372 completed、148 abstain。
- [x] 所有可扫描样本 before/after tree hash 一致，只观察到三个允许的本地分析器。
- [x] 独立复算指标、混淆矩阵、错误切片、吞吐和输出 SHA-256。
- [x] 556 条重叠样本复现检查无决策或规则集合漂移。
- [x] 后端测试 `73 passed`。
- [x] 生成 `docs/M2_SKILLTRUSTBENCH_FULL_REPORT.md`。

## M3 开发/回归边界与缺口分析

- [x] 将 5,520 条全量运行、指标契约、策略、数据清单、代码和报告按 SHA-256 冻结。
- [x] 生成 120 条开发集：60 漏报、40 正常误报、20 正确对照。
- [x] 生成 600 条标签均衡回归集：三类各 200 条。
- [x] 验证开发/回归 ID 零重叠，全部标签和 case tree hash 与全量 manifest 一致。
- [x] 确认回归抽样不使用父扫描结果，本轮未打开回归样本正文。
- [x] 对 120 条开发样本做只读文本特征分析，前后 hash 无变化且不保留原始文本。
- [x] 得到 39/41/9/8/2/1/20 的静态规则、证据关联、语义复核、校准、策略分离、动态验证和对照路线。
- [x] 重复运行验证 6 个关键划分/分析产物 SHA-256 完全一致。
- [x] 后端自动测试达到 `78 passed`。
- [x] 生成 `docs/M3_SKILLTRUSTBENCH_DEV_REGRESSION_AND_RULE_GAPS.md`。
- [x] 实现第一批下载—解码—执行与持久化规则；接入统一 Finding、策略和 API，开发集目标补出 21/36、T06 12/12、正确对照零回退、normal 零决策升级。
- [x] 实现网络声明—行为—敏感数据流 INFO 旁路证据：网络误报覆盖 16/16，决策变化 0/36，正确对照 20/20 不变。
- [x] 实现文件系统声明—实际读写—路径敏感性—高风险修改 INFO 旁路证据；v2 覆盖 8/8，决策不变 28/28，测试 112 passed。
- [x] 实现命令声明—调用方式—参数来源—测试夹具—危险命令 INFO 上下文证据；v2 覆盖 6/6、机制 5/5、决策不变 26/26、测试 126 passed。
- [x] 冻结规则和语义提示词后，一次性运行 600 条回归集配对评测；结果为 `supported_with_tradeoff`，不再用该回归集调规则。
- [x] 实现最小安全动态 fixture CLI：最终 v2 为 3/3、机制 7/7、负面指标全 0、测试 136 passed；只运行哈希锁定自建脚本，网络仅回环，数据集读取/执行 0。

## M4 动态证据核心 v1

- [x] 完成论文、开源项目、数据集、本地模型和安全边界技术选型文档。
- [x] 新建 `dynamic-audit-v1` 分支，静态最终决策逻辑保持不变。
- [x] 实现五类政企 Marker profile 和原文/Base64/Hex/URL/分片匹配。
- [x] 实现静态 Finding 到 Skill/MCP Trigger Plan。
- [x] 实现 potential/observed/confirmed/inconclusive 独立关联。
- [x] v1 发现计划类型关联过宽，原样保留并在 v2 增加计划内 profile 约束。
- [x] v2 完成 1/1 fixture、3/3 事件、1 条 Base64 witness、0 泄露、0 决策变化。
- [x] 动态专项测试 22 passed，完整后端测试 270 passed。
- [x] Docker 安全执行后端：已启动 Docker Desktop 并完成 40/40 安全门；仍未执行第三方样本。

## M4 D2 Docker 安全执行底座

- [x] 通过用户授权启动已有 Docker Desktop，确认 Linux Engine 29.7.2 / API 1.55。
- [x] 固定本地 Python 3.12-slim 镜像 digest/ID，强制 pull=never。
- [x] 配置拒绝浮动 tag、联网、特权、host PID、可写根和 capability 放宽。
- [x] create 后真实 inspect 24 项全部通过才允许 start。
- [x] 自建 probe 运行时 12 项行为门通过：非 root、cap=0、NNP/seccomp、只读根/输入和有界 tmpfs。
- [x] 镜像 4/4、inspect 24/24、runtime 12/12，合计 40/40。
- [x] 成功、非法 ID 和启动超时清理路径有测试；真实运行容器残留 0。
- [x] Docker 专项 26 passed，完整后端 296 passed。
- [x] 第三方样本、互联网、镜像拉取、GPU、云和静态决策变化均为 0。
- [ ] D2-B：strace、文件差分/inotify 和内部 sinkhole 遥测。
- [ ] D3：自建 MCP 协议 initialize/tools/list/tools/call 与 Marker witness 闭环。

## P0-1 可移植启动与换机复现

### 计划与边界

- [x] 两份评委审查文档提交并推送到 `origin/dynamic-audit-v1`。
- [x] 冻结基线提交 `3d98c85`，不修改检测规则、策略和动态安全边界。
- [x] 记录可移植启动的研究问题、最小代码图、停止条件和验收指标。

### 实现

- [x] 移除 `start_demo.ps1` 中的个人绝对 pnpm 路径。
- [x] 新增 pnpm/Corepack 与 Docker CLI 的共享可移植发现逻辑。
- [x] 新增人可读和 JSON preflight，区分必需能力、动态警告和 `-RequireDynamic`。
- [x] 新增固定 Cisco 官方仓库/提交、哈希锁依赖的运行时重建脚本。
- [x] 更新 QUICKSTART，明确在线重建、离线 wheel 和许可证边界。
- [x] 增加防止个人路径回归和模拟异用户环境的自动测试。

### 验证与封口

- [x] 默认 preflight 必需失败数为 0。
- [x] 模拟不同 USERPROFILE 且不依赖 Codex pnpm 路径时 preflight 通过。
- [x] 改造后的启动、v1 health 和停止流程通过。
- [x] 后端完整测试、前端测试和生产构建通过。
- [x] 固定运行证据、源码哈希、claim validation 和下一步决策。

## M5 全部工程收敛

- [x] 用户确认范围为 M5 全部 P0/P1/P2，不包含 PPT/视频/答辩材料。
- [x] 用户授权里程碑验收后自动提交并推送。
- [x] 用户授权引入已锁定、已核验依赖，第三方不可信样本继续不执行。
- [x] P0-5 验收环境固定为 Windows Sandbox，不以目录模拟代替。
- [x] P0-2 动态全局互斥、FIFO、有界队列、去重/冷却和重启恢复。
- [x] P0-3 单一当前状态真值与历史文档替代标记。
- [x] P0-4 精确依赖、共享运行时安全覆盖、项目许可、第三方声明、自身 SBOM 和自扫描。
- [ ] P0-5 Windows Sandbox 四链端到端发布门。
- [ ] P1 静态隔离、独立评测、任务体验、CI 和能力健康。
- [ ] P2 身份/租户、持久任务平台、强沙箱、治理、完整准入与可观测性。
- [ ] 最终全量验证、评委复审、版本冻结和发布。
