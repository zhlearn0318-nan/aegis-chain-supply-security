# PLAN：OpenClaw Skill 动态准入真实 E2E v1

## 1. 目标

- run id：`2026-08-27-openclaw-skill-dynamic-e2e-v1`
- 目标：让真实 OpenClaw 稳定版在本地 Skill 安装提交前调用 Aegis Chain `required` 动态策略，验证允许、动态升级阻断和异常失败关闭三条链。
- 零假设：OpenClaw 没有调用动态策略、危险样本在安装后才被发现、设施异常仍可能安装，或测试污染用户默认工作区。
- 备择假设：安全 Skill 安装成功；静态 ALLOW 的 Shell 样本被动态 CRITICAL 证据升级为 BLOCK；无效动态配置被阻断；两类阻断均无安装残留。

## 2. 固定用例

| 用例 | 静态对照 | required 动态预期 | OpenClaw 预期 |
| --- | --- | --- | --- |
| `safe_skill` | ALLOW | ALLOW | 安装到隔离 workspace |
| `shell_spawn_skill` | ALLOW | BLOCK / `AEGIS_DYNAMIC_SHELL_SPAWN` | 安装前阻断、无目录 |
| `safe_skill` + 无效动态模式 | ALLOW | 配置失败关闭 | 安装前阻断、无目录 |

样本均为项目自建并绑定 SHA-256，不执行第三方 Skill。

## 3. 安全与隔离

- 使用仓库内全新 state、workspace、profile、temp 和审计数据库；
- 同时设置 `OPENCLAW_CONFIG_PATH`、`OPENCLAW_STATE_DIR` 与 `agents.defaults.workspace`；
- OpenClaw 只接收显式最小环境，install policy `passEnv=[]`；
- 目标 Skill 动态执行继续使用固定镜像、`pull=never`、`network=none`、非 root、只读根、cap-drop ALL 和资源限制；
- 不修改用户原 OpenClaw 配置，不覆盖既有 Skill，不使用 `--force`；
- 结束后验证用户默认 workspace 没有三个测试 slug，Docker 容器残留为 0。

## 4. 接受标准

- OpenClaw 版本和本地入口身份已记录；配置校验通过；
- 安全安装 exit 0，目标目录存在；
- 动态高危和配置异常均 exit 非 0，目标目录不存在；
- 审计链有效并能分别证明 allow、动态 Shell block、配置异常 block；
- 输入源码前后哈希一致；
- 非预期安装残留、默认用户 workspace 污染、Docker 残留均为 0。

## 5. 边界

该实验验证当前 OpenClaw 2026.7.1-2、本机 Docker Desktop 和自建 Python fixture 的安装前闭环，不证明任意第三方 Skill 可被安全执行，不证明 Docker 等价于独立恶意代码虚拟机。
