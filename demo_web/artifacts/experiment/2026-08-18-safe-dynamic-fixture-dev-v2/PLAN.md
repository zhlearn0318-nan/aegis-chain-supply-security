# 最小安全动态 Fixture v1 实验计划 v2

- run id：`2026-08-18-safe-dynamic-fixture-dev-v2`
- parent：`2026-08-18-safe-dynamic-fixture-dev-v1`
- tier：`auxiliary/dev`
- 固定不变：三份 fixture 及其 SHA-256、7 项预期事件、Windows/Python、回环网络、5 秒超时、INFO-only、数据集读取/执行 0、门禁变化 0。
- 校准变量：相对路径按实际 cwd 解析；chdir 只能进入 workspace；符号链接/硬链接一律拒绝；Windows 命令行证据显式标为 `argument_form=windows_command_line` 且不伪报 argv 数量。
- 预期：3/3、7/7、违规/超时/泄露/非 INFO 均 0；安全专项测试从 8 项增加到 10 项；完整测试无回退。
- 边界：仍是哈希锁定自建 Python fixture 的协作式观测器，不是不可信代码沙箱。
- next：冻结动态证据 v1 契约与限制文档，再评估管理员专用平台接入。
- execution interface：`bash_exec`/artifact/memory 不可用，继续使用不可覆盖目录、日志、manifest 和 SHA-256。
