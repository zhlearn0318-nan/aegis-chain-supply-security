# D3 冒烟测试记录

## 首次执行

- 命令：`python -m pytest backend/tests/test_mcp_protocol.py -q`
- 结果：`2 passed, 10 errors`
- 分类：环境层，不是实现层失败。
- 原因：pytest 默认使用 `C:\Users\23684\AppData\Local\Temp\pytest-of-23684`，当前受限环境无法访问。
- 处理：不修改测试和评价逻辑，仅将 `--basetemp` 指向本实验目录。

## 环境修正后执行

- 命令：`python -m pytest backend/tests/test_mcp_protocol.py -q --basetemp artifacts/experiment/2026-08-23-mcp-protocol-marker-dev-v1/pytest-temp-smoke`
- 结果：`12 passed in 0.14s`
- 结论：配置锁定、真实 stdio 序列、未知工具/非法参数错误、调用前后 Marker 对照、静动态确认、脱敏和超时清理路由均通过冒烟测试。
- 性质：只验证本地代码路径；不替代真实 Docker 主运行。
