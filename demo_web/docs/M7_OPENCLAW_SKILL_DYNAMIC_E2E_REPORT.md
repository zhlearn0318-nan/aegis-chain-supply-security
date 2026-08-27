# M7 OpenClaw Skill 动态准入真实 E2E 报告

> 验证日期：2026-08-27
>
> 分支：`skill-dynamic-sandbox-v1`
>
> 最终 run id：`2026-08-27-openclaw-skill-dynamic-e2e-v2`
>
> 结论：`supported_real_openclaw_required_dynamic_admission`

## 1. 验证目标

让真实 OpenClaw `2026.7.1-2 (0790d9f)` 在 Skill 安装提交前调用 Aegis Chain `required` 动态策略，证明：

- 安全 Skill 经静态和动态审计后可以安装；
- 静态 ALLOW 的高危运行行为能够被动态证据升级为 BLOCK；
- 动态策略配置异常时失败关闭；
- 阻断发生在安装前，不产生目录或容器残留。

## 2. 用例选择

| 用例 | 静态对照 | 动态/平台结果 |
| --- | --- | --- |
| `safe_skill` | ALLOW | 动态 ALLOW，OpenClaw exit 0，安装成功 |
| `shell_spawn_skill` | ALLOW | `AEGIS_DYNAMIC_SHELL_SPAWN` / CRITICAL，OpenClaw exit 1 |
| `safe_skill` + 无效动态模式 | ALLOW | `AEGIS_DYNAMIC_POLICY_CONFIG_INVALID`，OpenClaw exit 1 |

外联和诱饵外传 fixture 已在静态层阻断，因此没有被用来宣称动态增益。全部执行对象为自建、SHA-256 锁定的 Python fixture；第三方样本执行数为 0。

## 3. 首轮失败与修复

v1 使用完全合成的 OpenClaw profile。Docker CLI 因找不到该 profile 下的 `desktop-linux` context，在容器创建前失败；系统正确产生 REVIEW 并由稳定版兼容模式阻断，但安全样本也无法安装。

只读对照确认，显式提供 Docker CLI context 后 Engine 29.7.2 可访问。v2 只向可信 Aegis install-policy 进程增加 `DOCKER_CONFIG`：

- OpenClaw `passEnv=[]` 保持不变；
- Cisco 扫描器继续使用独立合成 profile；
- Docker 配置不挂载进目标容器；
- 目标容器权限和检测规则均未放宽。

v1 失败结果和根因分析保留在独立证据目录，没有覆盖为成功。

## 4. 最终结果

- 用例通过：3/3；
- 审计链：有效，3 行；
- 审计证据门：3/3；
- 安全安装：1 个预期隔离目录；
- 阻断安装残留：0；
- 非预期隔离 workspace 条目：0；
- 用户默认 workspace 测试 slug：0；
- 输入源码哈希变化：0；
- Docker 容器残留：0；
- 总耗时：88.576 秒；
- GPU、云服务和第三方样本：均未使用。

## 5. 可以表述的结论

> Aegis Chain 已被真实 OpenClaw 稳定版作为 Skill 安装前策略调用。系统能够放行静态与动态均安全的 Skill，并将静态 ALLOW、运行时启动 Shell 的候选升级为 BLOCK；策略配置异常同样在安装提交前失败关闭。

## 6. 不主张

- 不主张可安全执行任意第三方或主动对抗型 Skill；
- 不主张 Docker Desktop/WSL2 等价于恶意代码专用虚拟机；
- 不主张 Python audit hook 不可绕过；
- 不主张已形成 Falco/eBPF 系统调用级旁证；
- 不主张当前结果已经满足真实政企生产发布要求。

## 7. 证据入口

- 最终成功：`demo_web/artifacts/experiment/2026-08-27-openclaw-skill-dynamic-e2e-v2/`
- 首轮失败：`demo_web/artifacts/experiment/2026-08-27-openclaw-skill-dynamic-e2e-v1/`
- 可复跑工具：`demo_web/tools/dynamic/run_openclaw_skill_dynamic_e2e.py`
