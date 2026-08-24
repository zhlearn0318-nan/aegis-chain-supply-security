# M5 P0-4 项目自身供应链卫生验收报告

> 状态：2026-08-25 已通过当前主机验收
> run id：`2026-08-24-project-supply-chain-hygiene-dev-v1`
> 基线：`08562f6`
> 结论：`project_supply_chain_gate_supported_at_2026-08-25_snapshot`

## 1. 本阶段解决了什么

本阶段审查的是 Aegis Chain 自己，而不是数据集样本。目标是让项目能回答五个评委常问的问题：用了哪些组件、版本是否可复现、是否有当天已知漏洞、第三方许可是否明确、仓库是否误带凭据。

最终建立了一条失败闭锁的自身供应链门：Web Python 子集、实际共享 Cisco/Aegis Python 环境、pnpm 安装图、许可证、CycloneDX SBOM、Secret 与仓库卫生必须同时通过，任何审计器错误或必需证据缺失都返回失败。

## 2. 初始问题与修复

| 初始问题 | 风险 | 修复 |
| --- | --- | --- |
| `python-multipart` 未精确固定 | 新机器可能得到不同版本 | Web 直接依赖全部精确固定并生成带哈希锁 |
| 前端 4 个直接依赖使用 `latest` | 构建不可复现 | 固定 React 19.2.8、Vite 8.2.0 等版本，锁定 pnpm 11.19.0 |
| `nanoid 3.3.16` 有 High 通告 | 构建工具链受已知漏洞影响 | 传递覆盖至 3.3.18，冻结安装后审计为 0 |
| 只审计 Web 15 包 | 会遗漏同一环境内 Cisco 依赖 | 增加实际共享运行时 `pip-audit --local`，覆盖 126 包 |
| Cisco 旧锁存在 19 个受影响包、118 条 OSV 记录 | 共享运行环境仍有已知风险 | 17 包哈希安全覆盖，补齐 2 个兼容依赖，`pip check` 与全环境审计通过 |
| 缺少根 LICENSE、NOTICE 与项目级 SBOM | 权属和交付组成不清 | 增加私有比赛许可、自动第三方声明、CycloneDX 1.6 SBOM |
| Cisco 子命令内部 pip-audit 失败时上游仍显示 SAFE | 空结果可能被误当无风险 | 复现脚本检查 stderr、JSON、状态、固定阳性/阴性 oracle，异常失败闭锁 |

## 3. 最终量化结果

| 指标 | 结果 |
| --- | ---: |
| 自身供应链 gate | 12/12 PASS |
| 实际共享 Python 组件 | 126 |
| Windows x64 已安装 Node 组件 | 26 |
| pnpm 锁内完整性组件 | 50/50 |
| CycloneDX SBOM 组件 | 152 |
| Web Python 已知漏洞 | 0 |
| 共享 Python 环境已知漏洞 | 0 |
| Node 已知漏洞 | 0 |
| 许可未知或越界 | 0 |
| 安装版本未被锁覆盖 | 0 |
| 已验证凭据泄露 | 0 |
| 仓库卫生违规 | 0 |
| 后端完整回归 | 348 passed |
| 前端测试/生产构建 | 10 passed / PASS |

Cisco 固定样本兼容冒烟中，Skill 集完成扫描；MCP 内容对象为 3 safe/3 unsafe；固定旧版 `urllib3` 样本得到 24 项 HIGH，固定安全样本为 0 项。这里的 24 会随漏洞数据库更新，不应当作为算法固定精度指标，只证明依赖扫描链路真实工作且阳性/阴性 oracle 均满足。

## 4. 如何复现

在仓库根目录执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\demo_web\audit_project_supply_chain.ps1" -WriteRepositoryArtifacts
```

输出目录默认是 `demo_web/data/project-supply-chain-latest/`；它属于本机临时证据，不提交。冻结证据位于 `demo_web/artifacts/experiment/2026-08-24-project-supply-chain-hygiene-dev-v1/`。根目录 `PROJECT_SBOM.cdx.json` 和 `THIRD_PARTY_NOTICES.md` 是可交付制品。

## 5. 技术边界

- “0 已知漏洞”只代表 2026-08-25 使用 OSV/pnpm 数据源得到的时间截面，新通告出现后必须重跑。
- 118 是初始 OSV 返回的数据库记录数，包含别名或重复映射，不等于 118 个独立 CVE。
- Secret 扫描使用高置信确定性模式，可降低误报并避免把原值写进报告，但不能证明所有形式的秘密都不存在。
- 许可清单用于工程交付核对，不构成法律意见；项目本体仍是私有比赛评估许可。
- Node SBOM 表示当前 Windows x64 实际安装图；跨平台可选包虽未声明为已安装，但 pnpm 锁中的完整性仍全部检查。
- 本阶段没有改变静态检测规则、M3 密封回归决策或动态安全边界。真正洁净 Windows VM 验收仍属于 P0-5，当前生产发布继续为 NO-GO。
