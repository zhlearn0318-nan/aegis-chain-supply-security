# Cisco Skill Scanner / MCP Scanner 复现快速入口

## 已安装位置

- Skill Scanner 源码：`third_party/skill-scanner`
- MCP Scanner 源码：`third_party/mcp-scanner`
- Skill Scanner 可运行环境：`.runtime_skill`
- MCP Scanner 可运行环境：`.runtime_mcp313`
- 离线 wheel 与锁定依赖：`results/wheels`、`results/*_locked_requirements.txt`

当前固定版本：

- Cisco Skill Scanner：提交 `4dee90371890ff23e1b21ea974e02847eacaa464`，包版本 `2.0.13.dev3+g4dee90371`
- Cisco MCP Scanner：提交 `51966cce214ae057e69c3a672307911f5026e255`，包版本 `4.8.2`
- Skill Python：3.11
- MCP Python：3.13；首次重建 `litellm==1.93.0` 时需要 Rust

## 一键复现

在 PowerShell 中执行：

```powershell
cd "F:\揭榜挂帅\supply_chain_reproduction"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run_all.ps1"
```

同时跑官方核心测试：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\run_all.ps1" -RunTests
```

脚本会：

1. 静态扫描 9 个 Skill 样例并计算混淆矩阵。
2. 扫描 MCP tool、prompt、resource 共 6 个样例。
3. 检测已知脆弱依赖与已修复依赖。
4. 对空结果和异常“安全”结果执行 fail-closed 校验。

依赖漏洞查询需要网络。Skill/MCP 的 YARA 与静态样例扫描不需要 API Key。

## 输出

- `results/skill_scanner_current.json`
- `results/skill_scanner_metrics_current.json`
- `results/mcp_static_current.json`
- `results/mcp_vulnerable_urllib3_current.json`
- `results/mcp_vulnerable_safe_current.json`
- `results/availability_summary.json`

## 单独调用

```powershell
.\.runtime_skill\Scripts\skill-scanner.exe --version
.\.runtime_skill\Scripts\skill-scanner.exe scan-all .\fixtures\skills --recursive --use-behavioral --format json --output .\results\skill_scanner_current.json
```

MCP Scanner 4.8.2 没有 `--version` 参数，可用包元数据查询：

```powershell
.\.runtime_mcp313\Scripts\python.exe -c "import importlib.metadata as m; print(m.version('cisco-ai-mcp-scanner'))"
```

原生 `static --output` 在该版本不会写文件，因此复现入口使用
`scripts/run_mcp_static.py` 捕获、校验并保存 JSON：

```powershell
.\.runtime_mcp313\Scripts\python.exe .\scripts\run_mcp_static.py `
  --scanner .\.runtime_mcp313\Scripts\mcp-scanner.exe `
  --tools .\fixtures\mcp\tools.json `
  --prompts .\fixtures\mcp\prompts.json `
  --resources .\fixtures\mcp\resources.json `
  --output .\results\mcp_static_current.json `
  --expected-unsafe 3
```

## 从锁定文件重建

推荐直接保留现有运行环境。若必须重建，请先安装 Conda，然后：

```powershell
conda create -p .\.build_skill311 python=3.11 -y
.\.venv_uv\Scripts\uv.exe venv .\.runtime_skill_rebuild --python .\.build_skill311\python.exe
.\.venv_uv\Scripts\uv.exe pip install --python .\.runtime_skill_rebuild\Scripts\python.exe --require-hashes -r .\results\skill_scanner_locked_requirements.txt
.\.venv_uv\Scripts\uv.exe pip install --python .\.runtime_skill_rebuild\Scripts\python.exe --no-deps .\results\wheels\cisco_ai_skill_scanner-2.0.13.dev3+g4dee90371-py3-none-any.whl
```

MCP Scanner 的 Windows 重建：

```powershell
conda create -p .\.build_mcp313 -c conda-forge python=3.13 rust=1.96 -y
.\.venv_uv\Scripts\uv.exe venv .\.runtime_mcp_rebuild --python .\.build_mcp313\python.exe
$env:PATH = "$(Resolve-Path .\.build_mcp313\Library\bin);$env:PATH"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
.\.venv_uv\Scripts\uv.exe pip install --python .\.runtime_mcp_rebuild\Scripts\python.exe --require-hashes -r .\results\mcp_scanner_locked_requirements.txt
.\.venv_uv\Scripts\uv.exe pip install --python .\.runtime_mcp_rebuild\Scripts\python.exe --no-deps .\results\wheels\cisco_ai_mcp_scanner-4.8.2-py3-none-any.whl
```

不要用 editable 安装把两个项目直接挂到含中文的路径；Python 3.11 在本机读取 UTF-8 `.pth` 时会按本地代码页解码并崩溃。现有环境通过非 editable wheel 规避了这个问题。
