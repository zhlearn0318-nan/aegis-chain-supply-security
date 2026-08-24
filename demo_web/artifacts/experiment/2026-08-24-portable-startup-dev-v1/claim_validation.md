# P0-1 声明验证与边界

| 声明 | 证据 | 判定 |
| --- | --- | --- |
| 活动启动链不再依赖开发者个人绝对路径 | 路径回归测试，命中 0 | 支持 |
| 静态审计启动前能识别必需组件和固定版本 | `preflight.json`，必需失败 0 | 支持 |
| 移除 Codex pnpm 路径后可使用 Corepack | `simulated_user_preflight.json`，Corepack pnpm 11.23.0 | 支持 |
| 缺少动态管理员条件时不会被误报为完整就绪 | 无 token 的 `-RequireDynamic` 负面测试，退出码 1 | 支持 |
| 当前机器可通过改造后脚本完成启停 | `startup_health.json`，v1 health 与停止通过 | 支持 |
| 现有 Cisco 运行时符合锁定版本 | `bootstrap_verify.json`，2/2 | 支持 |
| 全新 Windows 机器可从零无人值守重建 | 未在独立洁净虚拟机执行 | 未支持，保留为 P0-5 |
| 系统已具备生产级高可用性 | 本轮只处理启动可移植性 | 未支持 |

补充限制：本轮不执行第三方样本，不评估新的检出率，不改变静态准入决策，也不将当前受控动态 fixture 称为不可信代码沙箱。
