# 复现结果摘要

## 环境

- Windows NT 10.0.26200.0，AMD64。
- Cisco AI Skill Scanner 2.0.12，Python 3.10.20。
- Snyk Agent Scan 0.5.15。
- pip-audit 2.10.1，CycloneDX Python 7.3.1，Python 3.12.13。
- 当前主机未安装 Docker，因此未执行需要容器沙箱的动态恶意样本。

## Skill 扫描结果

判定阈值为 HIGH/CRITICAL。真值集包含 2 个良性与 7 个防御性恶意样本。

| 方案 | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Cisco 静态/字节码/管道 | 2 | 1 | 1 | 5 | 0.667 | 0.286 | 0.400 | 0.500 |
| Cisco + 行为数据流 | 2 | 1 | 1 | 5 | 0.667 | 0.286 | 0.400 | 0.500 |

行为数据流未改变样本级分类，但把总发现数从 16 增至 19，把 CRITICAL 发现从 2 增至 4；新增证据集中在“环境变量读取 + HTTP 外传”的跨文件链路。漏报包括下载执行、语义型提示注入、伪装只读的持久化，以及拆分在两个 Skill 中的组合触发链。良性安全培训文档因引用攻击短语被判 HIGH，形成 1 个误报。

## 其他工具

- Snyk Agent Scan 成功发现隔离 OpenClaw 目录中的 9 个 Skill，并枚举其中的 instruction、script、asset。云端判定需要上传 Skill 内容与元数据，未获授权，故未执行。
- pip-audit 对 `requests==2.19.0` 及其解析依赖报告 23 条已知漏洞；对单独锁定的 `urllib3==1.24.1` 报告 14 条已知漏洞。两者同时放入同一 requirements 会产生依赖冲突，这也是供应链可复现性信号。
- CycloneDX Python 生成了规范版本 1.6 的 SBOM，包含 requests 与 urllib3 两个直接组件。
- Cisco 安装在 Windows 中文路径上需要手工拆分依赖闭包；GuardDog 的 `nono-py` 依赖未能在当前 Windows 环境完成构建；Sentry 仓库浅克隆因连接重置失败。

## 结论

单一静态扫描器不能作为放行证据。竞赛方案应把自然语言语义、脚本/AST、依赖/SBOM、来源签名、隔离动态行为、跨 Skill/MCP 组合链和运行时策略统一到同一证据模型中，并对每一层单独评测。
