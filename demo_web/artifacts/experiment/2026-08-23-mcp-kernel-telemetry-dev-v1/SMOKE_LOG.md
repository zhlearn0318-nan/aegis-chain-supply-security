# D3-B 冒烟测试记录

- MCP 专项：`13 passed in 1.17s`。
- 动态 Marker、Docker 与 MCP 三组：`51 passed in 1.36s`。
- 通过内容：父实验协议与 Marker 逻辑、配置哈希锁、inotify 三类事件门、procfs 父子/fd 门、进程脱敏门、缺失 ACCESS 事件失败闭锁、启动超时清理。
- 性质：本地单元与模拟路径通过，不替代真实 Linux Docker 内核遥测运行。
