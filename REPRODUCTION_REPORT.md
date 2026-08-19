# Cisco Skill Scanner 与 MCP Scanner 复现及可用性报告

复现日期：2026-07-31  
平台：Windows 10 中文版，x64  
结论：两者均已安装并能运行；适合作为赛题代码底座，但不能直接作为最终检测方案。

## 1. 官方仓库与固定版本

- [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner)
  - 提交：`4dee90371890ff23e1b21ea974e02847eacaa464`
  - 本地包：`2.0.13.dev3+g4dee90371`
- [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner)
  - 提交：`51966cce214ae057e69c3a672307911f5026e255`
  - 本地包：`4.8.2`

源码、wheel、锁定依赖、运行环境和样例都在
`F:\揭榜挂帅\supply_chain_reproduction`，不依赖全局 Python 包。

## 2. 安装结果

### Skill Scanner

安装成功，CLI 版本自检成功。官方仓库的 editable/uv 环境在中文路径下生成 UTF-8 `.pth`，Python 3.11 会按 GBK 读取并触发 `UnicodeDecodeError`。最终做法是从固定提交构建 wheel，再安装到独立 Python 3.11 运行环境。

### MCP Scanner

安装成功。官方推荐 Python 3.13；锁定的 `litellm==1.93.0` 在 Windows 上没有直接可用的对应 wheel，需要 Rust 从源码编译。最终环境为 Python 3.13.14 + Rust 1.96.0。首次构建耗时明显高于 Skill Scanner。

MCP CLI 可以显示帮助并执行子命令，但 4.8.2 没有 `--version` 参数；版本通过 Python 包元数据确认。

## 3. 功能与测试证据

### Skill Scanner 官方核心测试

- 目标测试：scanner、YARA 真阳性、behavioral。
- 结果：`139 passed, 6 skipped, 1 xfailed`。
- 另发现两个 Windows 兼容性点：
  - 符号链接测试需要 Windows 开发者权限，普通用户会触发 `WinError 1314`。
  - 一个 `__pycache__`/父源码匹配测试在 Windows 路径分隔符下失败。

### Skill Scanner 本地标注样例

9 个完全静态、不会访问真实网络的样例：2 个良性、7 个恶意。以 `HIGH/CRITICAL` 为拦截阈值：

| 指标 | 结果 |
|---|---:|
| TP / TN / FP / FN | 2 / 1 / 1 / 5 |
| Accuracy | 0.3333 |
| Precision | 0.6667 |
| Recall | 0.2857 |
| F1 | 0.4000 |

命中：
 
- 凭据外传
- 混淆载荷执行

漏报：

- 下载并执行
- 语义 Prompt Injection
- 描述与行为不一致/持久化
- 两个拆分到不同 Skill 的跨组件攻击阶段

误报：

- 安全培训材料中用于解释攻击的 “ignore previous instructions” 被当成恶意指令。

因此，Skill Scanner 的工程框架、规则加载、报告结构和基础分析器可用；离线默认能力的召回率不足，恰好为赛题的跨 Skill 调用链、语义消歧和动态验证留下创新空间。

### MCP Scanner 官方核心测试

- YARA、规则覆盖、依赖漏洞分析器：`114 passed`。
- 扩展运行 static analyzer 测试时，144 个测试体通过，但 23 个 teardown 因测试夹具没有在 Windows 删除前关闭 `NamedTemporaryFile` 而报 `WinError 32`；这是测试兼容性问题，不是扫描断言失败。

### MCP 静态样例

对 tool、prompt、resource 各设置 1 个良性和 1 个恶意样例：

| 类型 | 良性 | 恶意 | 结果 |
|---|---:|---:|---|
| Tool | 1 | 1 | 2/2 正确 |
| Prompt | 1 | 1 | 2/2 正确 |
| Resource | 1 | 1 | 2/2 正确 |
| 合计 | 3 | 3 | 6/6 正确 |

恶意内容覆盖 Prompt Injection、凭据读取和数据外传。该结果证明 YARA 离线链路可用，但样本很小，不能解释为普遍 100% 准确率。

### 依赖漏洞检测

- `urllib3==1.24.1`：检出 14 条漏洞记录，均为 HIGH。
- `requests==2.33.0` + `urllib3==2.7.0`：0 条漏洞。

首次验证暴露了一个严重的 fail-open 行为：当 `pip-audit` 不在 PATH 或中文路径未启用 UTF-8 时，MCP Scanner 记录错误，但返回码仍为 0，并生成“SAFE”结果。一键脚本已固定 PATH、`PYTHONUTF8=1`，并对空/异常安全结果做二次校验；比赛系统中必须保留这层 fail-closed 门禁。

## 4. 已知边界

1. 当前没有 Cisco AI Defense、LLM 或 VirusTotal API Key，因此没有验证云端/API/LLM/meta 分析器。
2. MCP behavioral 分析明确需要 LLM Key；无 Key 时返回错误，不能离线使用。
3. Skill behavioral 虽可离线启动，但本地结果说明它并不能稳定识别描述—行为不一致和跨 Skill 链。
4. MCP `static --output` 在 4.8.2 接受参数但不写文件；复现脚本用 `scripts/run_mcp_static.py` 捕获并验证 JSON。
5. 两个 CLI 对“发现风险”通常仍返回 0，不能直接拿进程返回码做 CI 阻断条件。
6. 当前样例规模只适合 smoke test；竞赛报告中的准确率、漏报率和误报率必须基于更大、分层、可审计的数据集。

## 5. 是否可作为赛题底座

建议采用，定位如下：

- Skill Scanner：复用文件发现、规则、AST/bytecode/pipeline、策略、SARIF/JSON 报告。
- MCP Scanner：复用 MCP 协议采集、tool/prompt/resource 扫描、YARA、依赖漏洞和多语言源码入口。
- 自研统一层：不要修改两个上游核心过深，在其上加统一 IR、风险证据图、跨 Skill/MCP 调用链、沙箱动态验证、中文语义消歧和 fail-closed 策略门禁。

“调用 Cisco 扫描器并汇总结果”不构成足够创新。最值得在一个月内实现、且与赛题供应链要求直接对应的创新点是：

1. 把 Skill、MCP tool、依赖包、文件、网络端点和敏感数据源统一成证据图。
2. 检测单个组件均低风险、组合后形成 `读取 → 编码 → 外传/执行` 的跨组件攻击链。
3. 对高风险链做受控动态验证，生成可回放审计日志。
4. 用“文档语境/安全培训语境”降低关键词误报，并将不确定结果进入人工复核，而不是直接放行。

## 6. 一个月建议

- 第 1 周：冻结两个上游版本，完成统一 JSON/SARIF 归一化、fail-closed 门禁和 30–50 个分层样例。
- 第 2 周：构建跨 Skill/MCP/依赖的证据图与调用链规则，优先补齐现有 5 个漏报类型。
- 第 3 周：加入 Windows 沙箱或容器动态验证，记录文件、进程、网络和环境变量访问。
- 第 4 周：扩充数据集，完成消融实验、误报/漏报分析、演示 UI、10 分钟视频和可复现实验包。

## 7. 复现入口

运行方式见 `QUICKSTART.md`。推荐入口：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run_all.ps1" -RunTests
```

详细机器可读结论见 `results/availability_summary.json`。
