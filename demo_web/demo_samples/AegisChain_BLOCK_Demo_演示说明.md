# Aegis Chain 高风险 Skill 演示说明

> 演示文件：`AegisChain_BLOCK_Demo_Skill.zip`  
> 演示目标：通过网页上传一个 Skill ZIP，展示静态扫描、证据归一化和 `BLOCK` 准入判定  
> 最近验证日期：2026-08-07

## 1. 演示前准备

在 `supply_chain_reproduction/demo_web` 目录启动系统：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\start_demo.ps1"
```

确认浏览器可以访问：

```text
http://127.0.0.1:8000
```

## 2. 现场操作步骤

1. 打开 Aegis Chain 网页。
2. 进入 Skill 上传扫描区域。
3. 选择同目录下的 `AegisChain_BLOCK_Demo_Skill.zip`。
4. 点击上传或开始扫描。
5. 等待任务从 `queued/running` 变为 `completed`。
6. 展开风险详情，依次展示严重等级、规则、证据位置和修复建议。
7. 最后展示系统给出的准入结论 `BLOCK`。

## 3. 当前固定版本下的预期结果

| 项目 | 预期值 |
|---|---|
| 扫描状态 | `completed` |
| 准入决策 | `BLOCK` |
| 总发现数 | 4 |
| CRITICAL | 1 |
| MEDIUM | 2 |
| INFO | 1 |
| UNKNOWN | 0 |

预期发现项：

| 严重等级 | 规则 | 展示意义 |
|---|---|---|
| CRITICAL | `DATA_EXFIL_HTTP_POST` | 发现可能通过 HTTP POST 向外部发送数据 |
| MEDIUM | `TOOL_ABUSE_UNDECLARED_NETWORK` | Skill 声明本地运行，但实现中出现未声明的网络能力 |
| MEDIUM | `SOCIAL_ENG_MISLEADING_DESC` | 描述与实际代码行为不一致 |
| INFO | `MANIFEST_MISSING_LICENSE` | Skill 元数据未声明许可证 |

最近一次真实上传验证：

```text
任务 ID：0caa39a01ace43a28c172283420013a4
扫描耗时：3799 ms
文件 SHA-256：9c71e481f9dc014415c190f9c325f23c9906dcc94d0737313f3bba5c3dafd9a6
```

不同机器的扫描耗时会变化；如果以后升级扫描器，发现项数量也可能变化，但当前固定环境已经验证为 `BLOCK`。

## 4. 推荐讲解词

> 这个 Skill 在说明文件中把自己描述为“只在本地进行 Markdown 格式化，不访问网络”，看起来像一个低风险工具。但是静态扫描发现，它的实现代码读取了令牌和云访问密钥等环境变量，并构造了向外部地址发送数据的 HTTP POST 请求。这既构成潜在数据外传，也说明组件声明与实际行为不一致。系统把不同规则产生的结果统一成标准证据，最终根据 CRITICAL 风险给出 BLOCK，阻止该组件进入智能体平台。

可以继续补充：

> 这里展示的不只是 Cisco 扫描器的原始输出。Aegis Chain 还负责上传校验、扫描任务管理、结果归一化、准入策略、历史记录和修复建议，因此可以作为独立安全网关接入统一平台。

## 5. 样例安全说明

- 该样例专门用于静态安全扫描；
- 网页当前使用 `LOCAL_STATIC_ONLY` 模式，不会执行上传的 Python 脚本；
- 风险函数只被定义，没有任何调用入口；
- 网络地址使用保留的 `example.invalid` 域名；
- 源文件明确标注“不得执行”；
- 即使如此，也不要在宿主机手工运行样例脚本。

样例源码保存在 `AegisChain_BLOCK_Demo_Skill_source`，方便讲解时对照：

```text
AegisChain_BLOCK_Demo_Skill_source/
├── SKILL.md
└── scripts/
    └── format.py
```

## 6. 演示异常处理

### 页面一直显示 queued 或 running

先等待约 5–10 秒并刷新任务详情。如果仍未完成，访问 `/api/health`，确认 Skill Scanner 的 `ready` 为 `true`。

### 页面返回 UNKNOWN

`UNKNOWN` 表示扫描失败或结果不完整，不是安全。重新启动服务后再上传；现场讲解时可以顺带说明系统采用“失败不放行”的策略。

### 页面拒绝上传

确认选择的是本说明同目录下的 ZIP 文件，而不是源码目录或 Markdown 说明文件。不要重新压缩整个 `demo_samples` 目录，否则 ZIP 内可能出现多个无关文件。

### 扫描结果数量与本文不同

先查看 `/api/health` 中 Skill Scanner 的版本。本文结果基于 `2.0.13.dev3+g4dee90371`；扫描器升级可能改变规则和发现项，但只要存在 HIGH 或 CRITICAL，系统仍应给出 `BLOCK`。

