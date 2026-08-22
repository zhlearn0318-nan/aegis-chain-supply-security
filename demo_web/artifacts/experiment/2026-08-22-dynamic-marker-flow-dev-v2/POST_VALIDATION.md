# v2 运行后验证

- 动态专项与旧安全 fixture 测试：`22 passed`。
- 后端完整测试：`270 passed`。
- 受控运行：1/1 fixture、3/3 预期事件、1 条 Base64 witness、关联 `confirmed`。
- 计划外 Marker 反例：只能得到 `observed`，不能得到静动态 `confirmed`。
- 证据目录搜索原始 Marker 格式前缀：0 条命中。
- 策略违规、超时、事件解析错误、外网、受保护样本读取/执行、静态决策变化：全部为 0。
- 临时 Marker 工作区：运行后已删除。
- `artifact_manifest.json` 中 9 个证据文件哈希/字节数：全部一致。
- `run_manifest.json` 中 6 个源码/fixture 哈希/字节数：全部一致。
- Docker：命令不可用，本轮未使用，也未执行第三方样本。
