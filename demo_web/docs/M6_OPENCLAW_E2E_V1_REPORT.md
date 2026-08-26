# M6 OpenClaw 安装前准入真实对接报告

> 验证日期：2026-08-26
> 开发分支：`openclaw-install-policy`
> M6-1 提交：`0a0d1ec`
> 结论：`supported_with_upstream_version_limits`

## 1. 验证目标

本轮不再只调用适配器，而是让真实 OpenClaw CLI 在 Skill 安装提交前调用 Aegis Chain，验证：

- 安全 Skill 可以完成安装。
- 恶意 Skill 被阻断且无安装残留。
- 中风险 REVIEW 在不支持 `warn` 的旧版中不会放行。
- 策略路径、命令或协议异常时失败关闭。
- 测试配置和 Skill 工作区不污染用户现有 OpenClaw。

## 2. 环境与版本

| 项目 | 实际值 |
|---|---|
| Windows 全局稳定版 | OpenClaw `2026.7.1-2` (`0790d9f`) |
| 隔离候选版 | OpenClaw `2026.8.1-beta.3` (`5831b80`) |
| Beta npm 完整性 | 与注册表 `sha512-8v+2Knr...DvuQ==` 完全一致 |
| Node | `24.15.0` |
| Python | `3.13.14`，项目 `.runtime_mcp313` |
| Cisco Skill Scanner SHA-256 | `B31B66FCE1B8466BA5C49E1084EE972B746E00D4EBDCAEAB78AD6B38A0DCE366` |
| 网络/GPU/Docker | 扫描链路均未使用 |
| 第三方样本执行 | 0 |

稳定版是 npm `latest`，Beta 只安装在仓库忽略的数据目录，没有升级或覆盖用户全局 OpenClaw。
Beta ACL 验证期间临时部署到用户 OpenClaw 工具目录的测试代理已完整移动回仓库隔离证据区；用户工具目录无本轮代理残留，既有配置未修改。

## 3. 对接过程中发现的真实问题

### 3.1 `OPENCLAW_STATE_DIR` 不等于 Workspace 隔离

只设置 `OPENCLAW_STATE_DIR` 时，第一次安全安装仍写入了用户默认工作区：

`C:\Users\23684\.openclaw\workspace\skills\aegis-safe`

该目录确认由本轮创建后，已可恢复地移动至仓库隔离证据目录；原工作区残留为 0，没有删除文件。随后在测试配置中显式设置 `agents.defaults.workspace`，后续安装全部进入仓库隔离工作区。

工程结论：任何测试、演示或平台包装器都必须同时设置 state dir 和 workspace，不能只设置前者。

### 3.2 解释器和脚本目录都必须可信

稳定版第一次安装因 Windows ACL 自动验证不可用而失败关闭；人工核验后，隔离配置启用稳定版提供的 `allowInsecurePath=true`。第二次又因 Python 策略脚本不在 `trustedDirs` 中失败关闭。

工程结论：`trustedDirs` 必须同时包含：

- `exec.command` 解释器父目录。
- `exec.args[0]` 策略脚本父目录。

两次失败均发生在安装提交前，没有产生 Skill 残留。

### 3.3 稳定版和 Beta 的 warn/ACL 能力不一致

- 稳定版 `2026.7.1-2` 的配置架构已经包含 `installPolicy`，但策略响应只接受 `allow/block`；收到 `warn` 会失败关闭。
- Beta `2026.8.1-beta.3` 接受新协议方向，但删除了 `allowInsecurePath`，并在真实 Windows 用户权限下把 `C:\Program Files`、`C:\Users` 等常见祖先目录判定为权限过宽。
- Beta `doctor --deep` 因上述路径门判定安装和更新将失败关闭，因此没有被选为比赛冻结依赖。

工程决策：

- 默认新协议继续输出 `warn`。
- 当前稳定版设置 `AEGIS_OPENCLAW_REVIEW_MODE=block`，将 REVIEW 明确降级为阻断。
- 无效兼容配置同样阻断。
- 等官方稳定版同时支持 warn 和可用的 Windows 路径验证后，再复验人工确认流程。

## 4. 真实结果

| 用例 | OpenClaw 结果 | 安装残留 | 结论 |
|---|---|---:|---|
| 路径 ACL 无法验证 | exit 1，fail closed | 0 | 通过 |
| 策略脚本目录未加入 trustedDirs | exit 1，fail closed | 0 | 通过 |
| 安全固定 Skill | exit 0，安装成功 | 1 个预期目录 | 通过 |
| 恶意外传 Skill | exit 1，`CRITICAL 2 条` | 0 | 通过 |
| 中风险网络 Skill，原始 warn | 稳定版拒绝 warn 并失败关闭 | 0 | 安全但不可确认 |
| 中风险网络 Skill，兼容模式 | exit 1，说明 REVIEW 被兼容阻断 | 0 | 通过 |

最终残留核验：

```json
{
  "safe_installed": true,
  "risky_residue": false,
  "review_residue": false,
  "original_workspace_test_residue": false,
  "recovered_copy": true
}
```

## 5. 自动测试

- 新增 REVIEW→block 和无效兼容模式失败关闭测试。
- 新增 Node 最小代理缺少路径配置时的失败关闭测试。
- 后端完整回归：`386 passed`，0 failed。
- 唯一警告为既有 FastAPI/TestClient 弃用提示，与本次准入逻辑无关。

## 6. 可以与不可以主张的内容

当前可以主张：

> Aegis Chain 已被真实 OpenClaw 稳定版调用，在隔离工作区完成安全 Skill 安装，并在安装提交前阻断恶意和需复核 Skill；策略路径异常同样失败关闭。

当前不可以主张：

- OpenClaw 可确认 `warn` 流程已经通过。
- Beta 已适合 Windows 比赛冻结或生产部署。
- `doctor --deep` 的安装策略项已经全绿。
- Plugin/MCP 安装包已经覆盖。
- 当前系统已达到生产政企平台标准。

## 7. 下一步

1. 比赛演示固定使用稳定版兼容模式，保证 ALLOW 可安装，REVIEW/BLOCK/异常均不放行。
2. M6-3 增加准入审计记录、扫描器环境变量白名单和部署前检查。
3. M6-4 再处理插件/MCP 安装包；在此前 `targets` 只配置 `skill`。
4. 关注 OpenClaw 后续稳定版；只有 Windows ACL 门和 warn 确认同时通过后，才把 REVIEW 从 block 恢复为 warn。
