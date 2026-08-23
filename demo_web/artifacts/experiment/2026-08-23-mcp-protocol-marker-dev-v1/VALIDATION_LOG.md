# D3 正式运行与验证记录

## 正式运行

- 第一次命令：使用 shell 中的短 `python` 命令，正常退出但未生成任何证据文件，因此不计为实验运行。
- 接受命令：使用 `E:\Anaconda3\python.exe` 完整路径执行相同 run id、配置和指标合同。
- 接受结果：`completed`，MCP 4/4，全部接受门 66/66。
- 容器内实际执行时间：1.463 秒。

## 独立验证

- 项目标签容器残留查询：0。
- artifact manifest：9 个已登记证据文件，哈希不一致 0。
- run manifest：5 个源/配置文件，哈希不一致 0。
- 证据目录原始 Marker 格式前缀命中：0。
- 动态专项：50 passed。
- 完整后端：首次用系统 Python 因缺少 FastAPI 在收集阶段失败；使用仓库既有 `.runtime_mcp313` 后为 308 passed。

## 结论

- 状态：`success`。
- claim：`supported_on_controlled_fixture`。
- baseline relation：扩展 Marker v2 和 Docker v2，不改变静态基线。
- failure mode：`none`。
- next action：增加 syscall、文件系统和进程级独立遥测。
