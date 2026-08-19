# Post-run validation

- 动态审计专项测试：10/10 passed；覆盖工作区外写入、实际 cwd 相对路径、workspace 外 chdir、链接拒绝、非回环/主机名/错误端口、当前 Python exact command line、fixture 哈希和三 fixture 集成。
- 后端完整测试：136/136 passed，标准入口为 `run_tests.ps1`。
- 主运行：3/3 fixture、7/7 预期机制；策略违规、超时、事件解析错误、非 INFO、原始 token 泄露、受保护样本读取/执行、互联网连接和决策变化均为 0。
- 证据正文搜索：三个固定 stdin/env/loopback token 命中均为 0；SkillTrustBench case、回归和受保护样本路径引用为 0。
- Windows 进程证据：`argument_form=windows_command_line`、`argv_count=null`，完整命令行 SHA-256 与父 Runner 生成值匹配；没有 shell。
- 网络：只创建一个 `127.0.0.1` 随机端口连接，服务端来源和载荷哈希匹配；无 DNS 或互联网。
- GPU/Docker/云/管理员权限：均未使用；第三方样本执行：0。
- artifact manifest、配置、三份 fixture 和四个核心源码的 SHA-256 在关闭实验前复核。
