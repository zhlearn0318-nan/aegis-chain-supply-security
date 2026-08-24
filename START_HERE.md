# 历史 Cisco 复现入口（2026-07-31 快照）

> 本文件不再是系统最终入口。项目当前状态与阅读顺序见 [`CURRENT_STATUS.md`](CURRENT_STATUS.md)，当前启动与换机流程见 [`QUICKSTART.md`](QUICKSTART.md)。以下命令仅用于复核 2026-07-31 的 Cisco 工具可运行性基线。

请以本文件和 `run_verified.ps1` 为准。

```powershell
cd "F:\揭榜挂帅\supply_chain_reproduction"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run_verified.ps1" -RunTests
```

该入口已于 2026-07-31 从头到尾验证通过：

- Skill Scanner：139 passed、6 skipped、1 xfailed。
- MCP Scanner：114 passed。
- Skill 标注集：TP=2、TN=1、FP=1、FN=5。
- MCP 静态集：3 个良性、3 个恶意，6/6 分类正确。
- `urllib3==1.24.1`：14 条漏洞；修复版本样例：0 条漏洞。
- 包含 UTF-8、PATH、非空输出和异常安全结果的 fail-closed 校验。

详细结论见 `REPRODUCTION_REPORT.md`，机器可读结果见
`results/availability_summary.json`。
