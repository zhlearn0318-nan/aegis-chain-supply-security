# M8 OpenClaw 第三方 Skill 动态准入现场验收报告

> 验收日期：2026-08-28
>
> 分支：`skill-dynamic-sandbox-v1`
>
> OpenClaw：`2026.7.1-2 (0790d9f)`
>
> 结论：`accepted_live_third_party_skill_admission`

## 1. 验收目标

本次验收不再使用自建恶意 fixture，而是从公开研究数据集 SkillTrustBench 中选择一组“正常样本—同功能恶意变体”，接入用户实际 OpenClaw 工作区，验证以下闭环：

1. OpenClaw 在 Skill 安装提交前调用 Aegis Chain；
2. 静态审计通过后才允许进入 Docker 隔离试运行；
3. 动态证据完整且未观察到阻断行为时，正常 Skill 可以安装；
4. 静态命中严重风险时，恶意 Skill 在执行前被阻断；
5. 安装结果、审计记录和容器清理结果均可复核。

## 2. 为什么选择这两个样本

数据集固定版本为 `762d5388b3a047b26df9679582af868a0e5b2c8f`，完整清单 SHA-256 为 `3a061cda6145151fbac0cbabfab7ee16e7ca60d50659eb45c73807dd037ba6ac`。

| 样本 | 数据集标注 | 选择原因 |
| --- | --- | --- |
| `case_00906` | `normal / safe_pool / productivity` | 只有 `SKILL.md` 和一个根目录 Python 主程序；仅使用 Python 标准库，不含外部 URL，适合验证正常业务 Skill 能否通过真实准入。 |
| `case_01084` | `malicious / injected / productivity`，风险 `T01/T04/T07` | 与正常样本名称相同，主程序 SHA-256 也完全相同，但修改了指令并增加隐藏的工具覆盖脚本，适合证明系统扫描的是完整供应链包，而不是只看名称或主程序。 |

这组样本的核心演示价值是：用户表面看到的功能和主程序不变，但供应链包中新增文件改变了安全结论。

## 3. 本轮开发改动

### 3.1 根目录单 Python 入口支持

第三方 Skill 不一定把脚本放在 `scripts/` 下。动态入口发现新增以下受限回退：

- `SKILL.md` 没有明确引用入口，且 `scripts/` 下没有候选时；
- 根目录恰好只有一个 `.py` 文件，才允许作为动态入口；
- 根目录有多个 `.py` 文件时，以 `ENTRYPOINT_AMBIGUOUS` 拒绝，避免猜测执行目标。

### 3.2 动态 ALLOW 证明

系统新增 `AEGIS_DYNAMIC_EXECUTION_CLEAN` 信息级证明。只有同时满足以下条件才生成：

- 后端身份为固定的 `aegis-python-skill-sandbox-v1`；
- 动态状态为 clean；
- 入口数量、运行数量和执行结果一致；
- 遥测完整；
- 镜像身份门和容器安全门全部通过；
- 容器已删除且无残留。

缺少任一证明时，即使某个动态函数返回 `ALLOW`，稳定模式也会失败关闭，不会安装。

### 3.3 可重复验收工具

新增 `demo_web/tools/dynamic/run_openclaw_third_party_skill_demo.py`，固定数据集版本、清单哈希、样本文件哈希和预期结果，并验证：

- 正常样本安装成功；
- 恶意样本安装失败；
- 恶意样本没有进入动态执行；
- 安装文件与来源逐文件一致；
- 审计链有效；
- 输入源码未被修改；
- Docker 无残留；
- 默认 OpenClaw 工作区不受隔离测试污染。

## 4. 实际 OpenClaw 接入方式

真实配置只新增 `security.installPolicy`，目标范围为 `skill`，动态模式为 `required`。模型、网关、会话、插件、认证和现有 Skill 配置均未改变。

策略代码和 Cisco Scanner 运行环境被复制到版本化发布目录，而不是直接信任开发目录。发布目录 ACL 只允许以下主体修改：

- 当前桌面用户；
- `NT AUTHORITY\\SYSTEM`；
- 本机管理员组。

当前 OpenClaw Windows 稳定版无法自动验证 NTFS ACL，因此在完成上述人工 ACL 核验后启用了 `allowInsecurePath=true`。该开关只跳过 OpenClaw 的路径 ACL 自动识别，不会关闭 Aegis 静态扫描、Docker 动态审计或失败关闭策略。若部署目录仍对普通用户可写，禁止启用该开关。

原 OpenClaw 配置已在用户 `.openclaw` 目录生成独立备份，备份文件不进入代码仓库。

## 5. 真实验收结果

| 验收项 | 结果 |
| --- | --- |
| OpenClaw 配置校验 | 通过 |
| 正常样本 `case_00906` | `ALLOW`，安装成功 |
| 正常样本策略执行时间 | 9,031 ms |
| 正常样本端到端安装时间 | 24,137 ms |
| OpenClaw 能力识别 | 内部名称 `meeting-notes-generator`，`eligible=true`、`modelVisible=true` |
| 动态清洁证明 | `AEGIS_DYNAMIC_EXECUTION_CLEAN` |
| 恶意样本 `case_01084` | `BLOCK`，安装失败 |
| 恶意样本策略执行时间 | 5,056 ms |
| 恶意样本端到端阻断时间 | 19,713 ms |
| 恶意样本关键规则 | `YARA_prompt_injection_generic`、`AEGIS_PARTIAL_REMOTE_EXEC_CHAIN`、`AEGIS_STATIC_PYTHON_PARSE_FAILED` |
| 恶意样本动态执行次数 | 0 |
| 恶意安装目录残留 | 0 |
| Docker 容器残留 | 0 |
| 审计哈希链 | 有效，3 行 |
| 正常样本安装文件 | 2 个来源文件逐文件一致，另有 1 个 OpenClaw 来源元数据文件 |
| GPU | 未使用 |

最终机器验收结果为 `accepted=true`。

## 6. 现场演示建议

建议按以下叙事演示，不需要单独开发 Web 页面：

1. 展示两个样本名称相同、主 Python 文件哈希相同；
2. 通过 OpenClaw 安装正常样本，展示安装成功，并在 Skill 列表中展示 `meeting-notes-generator` 可用且模型可见；
3. 展示审计记录中的静态摘要和 `AEGIS_DYNAMIC_EXECUTION_CLEAN`；
4. 通过 OpenClaw 安装恶意变体，展示 CRITICAL 阻断；
5. 展示恶意目录不存在、恶意样本没有动态规则、容器残留为 0；
6. 总结为“静态审查决定是否有资格试运行，动态审计决定本次受控执行是否可接受，最后由 OpenClaw 在安装提交前执行准入决定”。

演示时不要把 INFO 解释为“绝对安全”。`AEGIS_DYNAMIC_EXECUTION_CLEAN` 只证明固定环境、固定输入和本次运行没有观察到阻断行为。

## 7. 失败过程与工程意义

首次真实安装时，OpenClaw 因 Windows ACL 自动验证不可用而失败关闭，正常和恶意样本都没有落盘。完成 ACL 人工核验并启用兼容声明后，正常样本才被放行，恶意样本仍被规则阻断。

该过程说明准入链路具有两个独立安全门：

1. OpenClaw 验证策略执行入口是否可信；
2. Aegis Chain 验证候选 Skill 是否可准入。

这次失败记录不应删除，因为它能证明系统在策略自身可信性不明确时确实选择了失败关闭。

## 8. 边界与后续工作

- 当前动态执行仅覆盖可确定入口的 Python Skill；
- Docker Desktop/WSL2 是比赛演示和工程验证环境，不等价于恶意代码专用虚拟机；
- Python 审计钩子不是不可绕过的内核级遥测；
- 网络为完全断开模式，尚未实现受控代理、域名白名单和流量内容审计；
- 未接入 Falco/eBPF/ETW 等第二信号源；
- 当前结果证明的是安装前闭环和样本级效果，不宣称可安全执行任意未知恶意 Skill；
- 面向正式政企生产部署时，应使用独立受控主机或虚拟机、集中审计存储、发布包签名和管理员审批。

在挑战杯作品范围内，这一阶段已经形成可现场演示的“第三方 Skill—静态审计—容器试运行—OpenClaw 安装/阻断—审计留痕”完整闭环。

## 9. 证据入口

- 隔离第三方 E2E 成功结果：`demo_web/artifacts/experiment/2026-08-28-openclaw-third-party-skill-demo-v2/`
- 隔离第三方 E2E 首轮失败记录：`demo_web/artifacts/experiment/2026-08-28-openclaw-third-party-skill-demo-v1/`
- 可复跑工具：`demo_web/tools/dynamic/run_openclaw_third_party_skill_demo.py`
- 现场一键程序：`demo_web/一键演示_OpenClaw_Skill准入.cmd`
- 一键程序主体：`demo_web/demo_openclaw_live_admission.ps1`
- 逐阶段讲解稿：`demo_web/docs/M8_OPENCLAW现场一键演示讲解稿.md`
- 实际 OpenClaw 安装目录：`%USERPROFILE%\\.openclaw\\workspace\\skills\\aegis-demo-meeting-safe`
- 实际审计数据库：`%USERPROFILE%\\.openclaw\\aegis-policy\\data\\admission_audit.db`
