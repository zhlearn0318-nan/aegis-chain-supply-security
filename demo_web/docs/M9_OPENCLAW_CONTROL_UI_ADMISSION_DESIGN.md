# M9 OpenClaw Web 控制台 Skill 准入演示设计

> 本文聚焦固定 Skill 准入演示页。报告、审计、规则、配置型 MCP 与 Windows 一键部署的最终状态，以 [`M10_OPENCLAW_FINAL_INTEGRATION_AND_WINDOWS_DEPLOYMENT.md`](M10_OPENCLAW_FINAL_INTEGRATION_AND_WINDOWS_DEPLOYMENT.md) 为准。

## 1. 目标

在 OpenClaw 浏览器控制台内新增“Aegis 准入”页，现场直接触发两条真实安装链路：

- `case_00906`：静态审计通过后进入 Docker 隔离试运行，动态清洁后允许安装；
- `case_01084`：静态规则命中后在安装提交前阻断，不执行恶意脚本，不生成安装目录。

## 2. 技术边界

OpenClaw 2026.7.1-2 原生 Skills 页只支持 ClawHub 搜索与安装，未提供本地目录或私有 ZIP 的选择控件。因此本实现使用官方插件扩展点：

- `registerControlUiDescriptor({ surface: "tab" })`：在控制台左侧导航注册页面；
- `registerHttpRoute(...)`：由同一个 OpenClaw Gateway 托管演示页面；
- 后台调用真实 `openclaw skills install`，安装过程继续强制经过 `security.installPolicy`。

没有修改 OpenClaw 的压缩前端文件，也没有把恶意样本发布到 ClawHub。

## 3. 安全约束

- 页面只接受 `safe` 和 `malicious` 两个枚举值；用户不能提交任意路径或任意压缩包。
- 两个样本的 `SKILL.md`、主程序和恶意附加文件均使用固定 SHA-256 校验。
- 页面加载时生成 256 bit 随机令牌，30 分钟后过期；接口只接受 JSON。
- 同一时间只允许一个准入任务，防止重复点击造成并发安装。
- 重置仅允许处理 `workspace/skills/aegis-web-safe-demo` 或 `aegis-web-malicious-demo` 两个精确目录。
- OpenClaw 安装策略、Docker required 模式和审计哈希链任一异常均失败关闭。

## 4. 演示链路

```text
OpenClaw Web 控制台
  -> Aegis 准入插件页面
  -> 固定样本身份与哈希核验
  -> openclaw skills install
  -> security.installPolicy
  -> Cisco Skill Scanner + 自研政企规则
  -> （仅静态允许时）Docker 隔离试运行
  -> ALLOW 安装 / BLOCK 阻断
  -> SQLite 审计哈希链
  -> 页面展示决策、规则、耗时和安装状态
```

## 5. 选择这两个 Skill 的原因

两个样本来自固定版本的 SkillTrustBench。它们使用相同业务名称，`meeting_notes_generator.py` 的 SHA-256 也完全相同，区别在于恶意变体篡改了 `SKILL.md` 并增加隐藏的工具覆盖脚本。因此这组样本能够说明：系统审查的是完整供应链包，而非仅凭名称、主程序或功能描述作判断。

## 6. 验收标准

- OpenClaw 左侧出现“Aegis 准入”入口；
- 正常按钮返回 `ALLOW`、动态清洁证明和安装成功；
- 恶意按钮返回 `BLOCK`、动态执行 0 次和安装残留 0；
- 两次结果均能在审计数据库中找到且哈希链有效；
- 页面不暴露本地任意路径、Gateway 令牌或任意命令执行能力。

## 7. 可视化执行与原始日志

页面底部固定展示统一执行终端，不再只在按钮旁显示最终结论。点击任一按钮后，Gateway 将 PowerShell 准入执行器的标准错误流转换为 NDJSON 流并实时传给浏览器；最终结构化结果仍单独返回，二者不相互替代。

终端按 `STEP 1/6` 至 `STEP 6/6` 展示以下真实阶段：样本与依赖预检、固定哈希核验、策略装载、真实 `openclaw skills install`、审计链核验和最终证据。长时间步骤每 5 秒输出一次 Gateway 心跳，以区分“仍在执行”与“页面无响应”。页面同步推进进度条，并在结束后固定展示数据集样本、最终决策、安装状态、端到端耗时、静态命中规则、动态审计结论、审计哈希链和主程序 SHA-256 八项证据。

日志来自真实子进程，不是前端预置动画或模拟文本。为避免演示泄露，Gateway 只对明显凭据、用户目录和项目目录做占位符脱敏，不改写命令语义或安全结论；恶意 Skill 在静态阶段阻断时会明确显示动态执行次数为 0，安全 Skill 才会进入 Docker 隔离试运行。

## 8. 2026-08-29 本机验收结果

| 验收项 | 实测结果 |
|---|---|
| 插件运行状态 | `loaded`；本阶段注册准入页与流式接口，M10 已扩展为五个侧边栏页面及管理接口 |
| 页面响应 | HTTP 200；生成后的 JavaScript 语法有效；流式读取、底部终端和阶段进度均存在 |
| 正常样本 | 28 条实时日志、6 个阶段；`ALLOW`；安装成功；Docker 隔离试运行清洁；审计链有效；28.250 秒 |
| 恶意样本 | 28 条实时日志、6 个阶段、3 条发现；`BLOCK`；未安装；动态执行 0 次；审计链有效 |
| 字符编码 | 两条链路均未出现 Unicode 替换字符，中文日志无乱码 |
| Web 接口端到端 | 两个固定样本均由 Gateway 流式接口真实触发，最终结构化结果与原始日志一致 |

这里的耗时包括 OpenClaw 命令启动、安装策略调用、静态扫描、Docker 动态试运行和审计写入，并非只代表 Cisco 扫描器本体耗时。恶意样本在静态阶段被阻断，因此不会为了演示效果而运行恶意脚本。

## 9. 现场入口

刷新 OpenClaw 控制台后，在左侧选择“Aegis 准入”，或访问：

```text
http://127.0.0.1:18789/plugin?plugin=aegis-admission-ui&id=admission
```

若左侧入口未立即出现，先确认 Gateway 已重启，再强制刷新浏览器页面。
