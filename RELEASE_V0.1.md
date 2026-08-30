# Aegis Chain 正式版 v0.1 发布说明

> 发布日期：2026-08-31
>
> 发布类型：挑战杯“揭榜挂帅”赛道竞赛正式版
>
> 目标环境：Windows 10/11、OpenClaw `2026.7.1-2`、Docker Desktop Linux Engine
>
> OpenClaw 插件版本：`4.1.0`

## 1. 版本定位

Aegis Chain v0.1 是 XA-202620 赛题“供应链安全”方向的正式提交基线。系统作为 OpenClaw 的安装前供应链安全引擎，对 Skill、Plugin、MCP 配置和 Python 依赖实施静态审计、策略决策、隔离试运行、安装门禁与审计留痕。

本版本已满足比赛现场演示和材料提交需要，但不是可直接部署到真实政企生产网的商业安全产品。身份权限、高可用、外部 WORM/SIEM、未知代码强隔离和第二台洁净 Windows 复现仍属于后续生产化工作。

## 2. 核心能力

### 2.1 静态供应链审计

- 集成 Cisco AI Skill Scanner、Cisco AI MCP Scanner 与 `pip-audit`；
- 自研敏感数据流、非可信输入到执行汇、网络/文件系统/命令上下文和政企控制规则；
- 统一 Finding IR、严重度、证据、SHA-256 指纹和四态决策：`ALLOW / REVIEW / BLOCK / UNKNOWN`；
- 内置规则冻结，自定义结构化规则或 YARA 规则可新增、修改、启用、停用并立即生效；
- 支持 CycloneDX SBOM、JSON、Markdown 和 PDF 报告。

### 2.2 Skill 安装前动态闭环

- 静态允许后才进入 Docker 隔离试运行；
- 容器内执行 Skill 脚本，限制网络、权限、资源、时间和文件系统边界；
- 识别网络、文件读写、进程创建、Shell、敏感环境变量等行为；
- 动态结果只能维持或提高风险，异常、超时和证据缺失均失败关闭；
- 扫描资格绑定内容哈希，安装前再次复核，阻断对象不会进入 OpenClaw 安装目录。

### 2.3 OpenClaw 正式集成

- OpenClaw 侧边栏只保留一个“Aegis 安全中心”；
- 包含安全总览、准入扫描、扫描报告、审计记录、规则管理和 MCP 准入六个模块；
- 支持上传 `.zip` 或选择本地 Skill 文件夹；
- `ALLOW` 后才能安装，同名 Skill 需用户确认并使用事务更新，失败恢复原版本；
- MCP 配置先审计，只有放行后才调用 OpenClaw 官方命令保存；
- 本地追加式审计记录使用 SHA-256 哈希链校验完整性。

### 2.4 2K 政企安全控制台

- 采用统一浅色政企管理界面，适配 2K 现场演示屏幕；
- 总览首屏展示真实准入数量、允许/阻断分布、审计链、最近活动和规则版本；
- 原始扫描日志保留深色终端区域，直接展示真实上传、静态扫描、动态审计和安装过程；
- 页面不使用虚构演示指标，所有统计均来自本机审计接口。

## 3. 一键部署

在目标 Windows 电脑安装并启动 Docker Desktop 后，将仓库完整下载到本地，双击根目录：

```text
Install_Aegis_OpenClaw_Final.cmd
```

安装器会固定 OpenClaw 版本、重建扫描运行时、配置 Docker 动态后端、备份并写入安全策略、安装插件、重启 Gateway，并执行正式预检。首次联网重建 Cisco 扫描环境耗时较长，完成后可复用。

安装完成后进入 OpenClaw Web 控制台，在侧边栏打开“Aegis 安全中心”。详细步骤见 [`QUICKSTART.md`](QUICKSTART.md) 和 [`demo_web/docs/M10_OPENCLAW_FINAL_INTEGRATION_AND_WINDOWS_DEPLOYMENT.md`](demo_web/docs/M10_OPENCLAW_FINAL_INTEGRATION_AND_WINDOWS_DEPLOYMENT.md)。

## 4. 已冻结验证证据

| 验证项 | v0.1 结论 |
| --- | --- |
| SkillTrustBench 全量静态基线 | 5,520 条完成扫描 |
| 规则开发集 / 密封回归集 | 120 条 / 600 条 |
| Skill Docker 稳定性回归 | 20 样本 × 3 轮，共 60/60 决策与必需规则通过 |
| OpenClaw 动态安装 E2E | 安全 Skill 安装、危险 Skill 阻断、配置异常失败关闭，3/3 通过 |
| 正式上传验收 | ZIP、文件夹、同名确认更新和恶意阻断真实 Edge 验收通过 |
| OpenClaw 统一安全中心 | 单侧边栏、六模块导航、真实接口和控制台零错误验收通过 |
| OpenClaw 插件测试 | 14/14 通过 |
| 后端冻结回归 | 466 passed，1 skipped |
| 前端 API / 生产构建 | 10 passed / 构建通过 |
| 项目自身供应链门 | 12/12 gate 通过；已知漏洞、已验证 Secret、许可越界和锁不匹配均为 0 |
| 审计完整性 | 本机追加式记录 SHA-256 哈希链有效 |

表中不同数据来自对应冻结里程碑，完整证据索引以 [`CURRENT_STATUS.md`](CURRENT_STATUS.md) 为准。时间截面测试结果不代表未来依赖或漏洞状态永久不变。

## 5. 仓库入口

- [`README.md`](README.md)：项目总览、能力和仓库结构；
- [`CURRENT_STATUS.md`](CURRENT_STATUS.md)：当前状态唯一真值、证据和限制；
- [`QUICKSTART.md`](QUICKSTART.md)：Windows 运行时重建、预检、启动和测试；
- [`SECURITY.md`](SECURITY.md)：安全边界和漏洞报告方式；
- [`demo_web/README.md`](demo_web/README.md)：Web 系统开发与使用说明；
- [`demo_web/openclaw_plugin/aegis-admission-ui/README.md`](demo_web/openclaw_plugin/aegis-admission-ui/README.md)：OpenClaw 插件说明；
- [`demo_web/docs/M11_OPENCLAW_FORMAL_SKILL_UPLOAD_ADMISSION.md`](demo_web/docs/M11_OPENCLAW_FORMAL_SKILL_UPLOAD_ADMISSION.md)：正式 Skill 上传准入合同；
- [`demo_web/docs/M12_OPENCLAW_UNIFIED_SECURITY_CENTER_RELEASE.md`](demo_web/docs/M12_OPENCLAW_UNIFIED_SECURITY_CENTER_RELEASE.md)：统一安全中心发布证据。

## 6. 已知边界

- Docker/WSL2 不等价于虚拟机级恶意代码隔离，不应执行高危未知样本；
- 当前动态能力主要覆盖 Skill，Plugin 运行时隔离和在线未知 MCP Server 不在 v0.1 承诺范围；
- 本地 SQLite 哈希链不等价于企业 WORM、可信时间戳或外部 SIEM；
- 当前为单机演示架构，尚未提供多租户、统一身份、高可用或分布式任务调度；
- 第二台洁净 Windows/真实 VM 验收未完成，不影响竞赛交付，但限制了生产发布主张；
- 静态或动态扫描未发现风险不等于绝对安全，扫描异常与 `UNKNOWN` 默认不放行。

## 7. 发布内容

GitHub Release `v0.1` 包含该标签对应的源代码归档。大规模数据集、第三方源码、Python/Node 运行环境、缓存、日志、SQLite 和本机扫描输出依据 `.gitignore` 不进入发布包；安装器会从固定上游提交和带哈希锁文件重建所需运行时。
