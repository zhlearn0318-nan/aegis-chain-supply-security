# OpenClaw Skill 动态准入真实 E2E v2 结论

真实 OpenClaw `2026.7.1-2 (0790d9f)` 已完成三条安装前动态准入闭环：安全 Skill 动态 ALLOW 并安装成功；静态 ALLOW 的 Shell Skill 被 `AEGIS_DYNAMIC_SHELL_SPAWN` 升级为 BLOCK；无效动态策略配置失败关闭。

最终用例 3/3、审计证据 3/3，审计哈希链有效。输入源码变化、阻断安装残留、非预期隔离 workspace 条目、用户默认 workspace 测试 slug 和 Docker 容器残留均为 0。后端完整回归为 418 passed、1 skipped。

v1 的 Docker context 发现失败已独立保留；v2 仅向可信策略父进程显式提供 Docker CLI context，没有把用户目录、Docker 配置或 Docker Socket 挂载进 Skill 容器。
