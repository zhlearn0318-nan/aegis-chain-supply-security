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
- [x] P0-5 验收环境固定为真实 Windows VM；Windows Sandbox、VirtualBox、VMware、QEMU 或 Hyper-V 均须提供硬件身份，不以目录/容器模拟代替。
- [x] P0-2 动态全局互斥、FIFO、有界队列、去重/冷却和重启恢复。
- [x] P0-3 单一当前状态真值与历史文档替代标记。
- [x] P0-4 精确依赖、共享运行时安全覆盖、项目许可、第三方声明、自身 SBOM 和自扫描。
- [x] P0-5 固定工具下载、VM/远端/新克隆证明、四链 HTTP、断网失败闭锁、导出和残留检查程序。
- [x] P0-5 真实 VirtualBox Windows guest、Guest Additions、受保护 guestcontrol、代理网络和引导文件跨边界哈希验证。
- [x] P0-5 临时单仓库只读 Deploy Key、严格 known_hosts、认证互斥和 guest 私钥删除合同。
- [x] P0-5 三次真实 VM 失败运行逐次固化证据，未把失败包装为通过。
- [x] 2026-08-26 确认 P0-5 非赛题强制交付物，调整为延期且不阻断比赛交付。
- [x] 吊销临时 GitHub Deploy Key，删除宿主私钥、公钥和该次专用 `known_hosts`。
- [ ] 可选后续：在比赛核心材料完成且仍有余量时，重新创建一次性认证并执行第四次全新 VM 运行。
- [ ] P1 静态隔离、独立评测、任务体验、CI 和能力健康。
- [ ] P2 身份/租户、持久任务平台、强沙箱、治理、完整准入与可观测性。
- [ ] 最终全量验证、评委复审、版本冻结和发布。

## M6 OpenClaw 安装前准入

- [x] 新建 `openclaw-install-policy` 分支。
- [x] 编写正式设计文档并冻结 protocol v1、失败关闭和能力边界。
- [x] 实现同步 Skill 安装策略适配器，不依赖 Web API。
- [x] 实现有界目录哈希、链接拒绝和扫描前后变化阻断。
- [x] 实现 ALLOW/REVIEW/BLOCK/UNKNOWN 到 allow/warn/block 映射。
- [x] 实现 UTF-8 单 JSON CLI 和 OpenClaw 配置示例。
- [x] 通过22个专项用例及后端完整 `383 passed`。
- [x] 真实安全/恶意固定 Skill 分别返回 allow/block。
- [x] M6-2：真实 OpenClaw 稳定版安装策略与 Skill allow/block/failure 闭环；`doctor --deep` 的稳定版兼容限制如实保留。
- [x] M6-2：真实 allow/block/failure 安装与无残留验证。
- [x] M6-2：旧稳定版 REVIEW→block 兼容验证。
- [ ] M6-2：新版可确认 warn 与 `doctor --deep` 安装策略全绿；当前受上游 Windows ACL 限制。
- [x] M6-3：扫描进程环境白名单和准入审计落盘。
- [x] M6-3：审计失败关闭、追加链校验和部署前安全/恶意固定样本检查。
- [x] M6-4：目录型原生 Plugin 与随包 MCP manifest 最小适配。
- [x] M6-4：真实 OpenClaw Plugin allow/block/无残留闭环。
- [ ] 生产增强：配置型 MCP 写入前准入、Plugin 单文件/归档和独立权威数据集。
- [x] 静态最终评委复核：比赛版本可冻结，生产继续 NO-GO。

## M7 Skill 安装前动态沙箱

- [x] 新建 `skill-dynamic-sandbox-v1` 分支并完成正式设计文档。
- [x] 实现 Python 入口发现、Docker 安全合同、动态行为规则和静动态单调融合。
- [x] 实现固定容器父启动器、Python audit hook、政企诱饵与容器内本地汇点。
- [x] OpenClaw 增加显式 `required` 动态模式；默认 `disabled` 保持静态冻结决策不变。
- [x] Docker Desktop 启动故障定位为本地残留 Unix socket；可恢复备份后关闭 Model Runner，Engine 恢复运行。
- [x] 固定镜像身份核验通过，运行期间 `pull=never`。
- [x] 良性、外连、诱饵外传、Shell、超时 5 类自建 fixture 绑定 SHA-256。
- [x] 真实 Docker 3 轮共 15 次执行：决策正确 15/15，误报/危险漏报/遥测缺失/清理失败/容器残留均为 0。
- [x] 真实 OpenClaw required E2E：安全安装、静态 ALLOW→动态 Shell BLOCK、配置异常失败关闭 3/3；审计证据 3/3，阻断/用户 workspace/容器残留均为 0。
- [x] OpenClaw 隔离 profile 的 Docker context 发现失败已保留；显式可信 `DOCKER_CONFIG` 修复有回归测试且不进入目标容器。

## M10 OpenClaw 最终集成与 Windows 部署

- [x] OpenClaw 左侧提供准入、报告、审计、规则、MCP 五个页面。
- [x] Skill 与 Plugin 安装自动调用 Aegis `security.installPolicy`。
- [x] 配置型 MCP 扫描后使用官方 `mcp set/show` 原子提交与复核；失败回滚。
- [x] 结构化规则/YARA 可新增、修改、启停、删除并立即生效，规则变更写入哈希链。
- [x] 准入报告可在本机导出 A4 PDF。
- [x] Windows 一键安装/修复完成固定版本、配置备份/回滚、Docker、策略、插件、Gateway 和完整预检。
- [x] 当前主机五页 HTTP 200、24项预检0警告、Skill/Plugin/MCP ALLOW+BLOCK 和41条有效审计链通过。
- [x] MCP 更新先快照旧值，写入后逐字段复核；提交或复核失败恢复旧配置。
- [x] 后端 `450 passed, 1 skipped`，前端 `10 passed`，生产构建通过。
- [ ] 第二台洁净 Windows 或真实 VM 完整一键部署证据（不阻断比赛交付）。
- [ ] 生产 SSO/RBAC、外部 WORM/SIEM、多实例高可用与专用恶意代码隔离。

## M11 OpenClaw 正式 Skill 上传准入

- [x] 用 ZIP/本地文件夹选择器替换固定样本准入卡片。
- [x] ZIP 50 MB、解压/文件夹 200 MB、5,000 文件和单文件 50 MB 边界。
- [x] 阻止路径穿越、链接、控制字符、Windows 保留名、非法字符和大小写冲突。
- [x] 扫描资格绑定源树 SHA-256，安装前重新核对，OpenClaw 原生策略二次复扫。
- [x] 只有 `ALLOW + 有效审计链` 才启用安装按钮；BLOCK/异常失败关闭。
- [x] 同名更新使用页面内确认、同盘暂存和失败恢复，不依赖浏览器弹窗。
- [x] 真实 Edge 验收：安全 ZIP 安装、安全文件夹同名更新、恶意文件夹阻断三类通过。
- [x] 58 条审计链有效；后端 `466 passed, 1 skipped`；上传边界 Node `10 passed`。
- [ ] 第二台洁净 Windows/真实 VM 正式上传与安装验收（不阻断比赛交付）。
- [x] 建立 20 个哈希锁定的自建动态样本，覆盖良性对照、进程、外连、诱饵/编码外传、敏感路径、动态加载和超时共 8 类行为。
- [x] v1 60/60 后发现 `os.system()` 风险标签偏宽松；不改写原始结果，提升为 Shell CRITICAL/BLOCK 并建立 v2。
- [x] v2 20 样本×3轮共60次真实容器执行：决策/规则 60/60，误报、漏报、复核错配、不稳定、遥测缺失、清理失败和残留均为0。
- [x] 后端完整回归 `422 passed, 1 skipped`；跳过项仅为 Windows 符号链接权限。
- [ ] 可选：Falco/eBPF preflight 与内核级交叉证据；失败不阻断默认 Python 后端。
- [ ] 第三方 Skill 风险试验；仅在更强隔离、单独授权和明确停止条件下开展。
