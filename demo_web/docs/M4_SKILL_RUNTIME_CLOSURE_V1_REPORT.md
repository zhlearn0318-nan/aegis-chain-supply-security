# M4：Skill 运行时目录闭包与静态提升 v1 报告

## 1. 结论

D3-C 已完成并通过验收。系统能够在固定、无网络、非特权 Docker 容器中运行自建且哈希锁定的 Skill fixture，记录 Skill 目录运行前后的完整文件清单，识别运行时新增的指令、脚本和配置，并将这些内容重新送入与正式准入 API 相同的 Cisco Skill Scanner + Aegis 静态审计链路。

本次真实运行全部 59 项接受门通过。初始目录含 2 个文件，运行后含 5 个文件；3 个新增文件全部识别、分类、提升并完成 SHA-256 验证。静态发现由运行前 2 条增至运行后 9 条，其中 2 条风险明确定位到运行时生成脚本：Cisco `PIPELINE_TAINT_FLOW` 为 HIGH，Aegis `AEGIS_REMOTE_FETCH_PIPE_SHELL` 为 CRITICAL。

这证明系统已形成“静态初审 → 受控运行 → 目录差分 → 新内容静态复审”的基本闭环。结论仅适用于自建受控 fixture，不代表当前系统可安全执行任意第三方 Skill。

## 2. 为什么需要这一能力

仅扫描安装包初始内容会遗漏运行时才出现的材料。例如，Skill 可以在启动后生成新指令、下载器脚本或放宽权限的配置。若审计系统只看运行前目录，这些内容将处于静态扫描盲区。

本模块将运行时新文件“提升”回静态分析：动态层负责证明文件是在运行后出现的，静态层继续负责判定其风险类型和严重度。这样既复用已有规则和 Cisco 工具，也保留可解释、可复核的文件路径、哈希、规则编号和严重度。

## 3. 实现内容

### 3.1 受控 fixture

- 只执行仓库内自建 Python fixture，配置中锁定相对路径和 SHA-256。
- 初始 Skill 只包含根 `SKILL.md` 与说明文件。
- 运行时生成且不执行三份审计素材：Markdown 指令、Python 脚本、JSON 配置。
- 容器使用固定 digest 镜像，`pull=never`、`network=none`、只读根文件系统、非 root 用户、丢弃全部 capability，并启用 `no-new-privileges`。

### 3.2 目录闭包

fixture 输出运行前和运行后清单，每项只声明相对路径、字节数、类别和 SHA-256。宿主侧不直接信任该声明，而是执行以下独立验证：

1. 拒绝绝对路径、`..`、反斜杠、空路径和大小写重复路径；
2. 限制文件总数、单文件大小和总字节数；
3. Base64 解码后要求 UTF-8 文本，并重新计算字节数和 SHA-256；
4. 要求初始文件未修改、未删除，新增路径和类型与固定合同完全一致；
5. 在临时目录重建运行前、运行后两棵 Skill 文件树，扫描完成后自动删除。

### 3.3 静态提升

新增 `run_skill_static_pipeline` 作为统一入口。正式 API 和动态闭包实验都通过该入口调用：

- Cisco Skill Scanner；
- Aegis 通用静态规则；
- 敏感数据流；
- 不可信输入到执行；
- 政企控制规则；
- 静态覆盖率；
- 网络上下文；
- 文件系统上下文；
- 命令上下文。

扫描运行前与运行后目录后，系统按规则、分析器、严重度、相对文件路径和行号计算差集。只有新增、非 INFO/SAFE 且定位到运行时文件的发现，才计入“运行时风险找回”。

### 3.4 隐私与策略边界

- 持久化证据不保存 Base64 内容或生成文件原文，只保留清单、哈希和脱敏发现。
- 供应商原始证据继续沿用现有哈希化规范。
- 动态证据给出运行前后策略建议用于解释，但 `policy_effect=none`；本阶段不自动改变既有最终准入决策。
- 不执行生成脚本，不执行第三方 Skill，不接受用户自定义命令、路径或代码。

## 4. 实验结果

| 指标 | 结果 |
|---|---:|
| 全部接受门 | 59/59 |
| 镜像身份门 | 4/4 |
| 容器配置门 | 24/24 |
| 运行时安全门 | 12/12 |
| Skill 闭包门 | 19/19 |
| 运行前 / 运行后文件 | 2 / 5 |
| 新增 / 提升 / 哈希验证 | 3 / 3 / 3 |
| 指令 / 脚本 / 配置 | 1 / 1 / 1 |
| 闭包覆盖率 | 100% |
| Cisco 扫描次数 | 2 |
| 静态发现（前 / 后 / 新增） | 2 / 9 / 7 |
| 定位到运行时文件的风险 | 2 |
| 完整后端回归 | 322 passed |

运行时风险如下：

| 来源 | 规则 | 严重度 | 定位 |
|---|---|---|---|
| Cisco Skill Scanner | `PIPELINE_TAINT_FLOW` | HIGH | `runtime/generated_action.py:1` |
| Aegis | `AEGIS_REMOTE_FETCH_PIPE_SHELL` | CRITICAL | `runtime/generated_action.py:5` |

负面指标全部为 0：不安全路径、软链接、超限文件、不支持文件、原文泄漏、第三方样本执行、互联网使用、镜像拉取、GPU 使用、最终决策变化、容器残留和超时。

## 5. 如何解释“运行前有 2 条发现”

运行前 2 条均不代表初始 Skill 已包含上述运行时攻击链。Aegis 会生成 INFO 级静态覆盖摘要，Cisco/Aegis 也可能对 Skill 元数据给出低风险或解释性结果。关键证据不是简单比较总数，而是比较稳定规则身份和文件定位：运行时脚本出现后，新增的 Cisco HIGH 与 Aegis CRITICAL 才被找回，运行前不存在相同路径上的相同风险。

## 6. 复现与证据

从仓库根目录运行：

```powershell
.runtime_mcp313\Scripts\python.exe demo_web\tools\dynamic\run_skill_closure_audit.py
```

固定证据位于：

- `demo_web/artifacts/experiment/2026-08-23-skill-runtime-closure-dev-v1/skill_closure_evidence.json`
- `demo_web/artifacts/experiment/2026-08-23-skill-runtime-closure-dev-v1/metrics.json`
- `demo_web/artifacts/experiment/2026-08-23-skill-runtime-closure-dev-v1/run_manifest.json`
- `demo_web/artifacts/experiment/2026-08-23-skill-runtime-closure-dev-v1/artifact_manifest.json`

运行入口默认拒绝覆盖已有证据，防止无意中改写已接受结果。

## 7. 评委视角的价值与边界

本轮价值不在于声称“容器能挡住一切攻击”，而在于形成了可说明、可测试、可追溯的研究闭环：运行前看不到的文件，在运行后被独立盘点并再次扫描；Cisco 与自研规则对同一运行时脚本给出相互补强的风险证据。

当前仍有三项边界：

1. 只执行自建 fixture，第三方 Skill 仍需审批、来源验证和更强隔离后才能进入执行范围；
2. 当前证明文件系统内容闭包，不提供系统调用级的“由哪个进程写入每个字节”归因；
3. 动态结果暂不改变最终决策，后续需在评测稳定后制定静动态联合准入策略。

因此，本阶段适合表述为“完成受控 Skill 运行时内容发现与静态再审机制验证”，不应表述为“完成通用恶意 Skill 安全沙箱”。
