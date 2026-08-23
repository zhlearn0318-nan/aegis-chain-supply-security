# D3-B MCP 内核辅助遥测结果

- 状态：`completed`
- MCP 协议步骤：4/4
- 全部接受门：82/82
- 内核遥测门：16/16
- 调用前 Marker witness：0
- 调用后 Marker witness：1
- 静动态关联确认：1
- inotify OPEN/ACCESS/CLOSE：1/1/1
- procfs 父子关系/fd 命中：1/1
- 独立文件读取确认：1
- strace 可用：0（仅记录，不作为失败门）
- 原始 Marker 泄漏：0
- 容器残留：0
- 第三方样本执行：0
- 静态最终决策变化：0
- 边界：仅证明受控 fixture 中 inotify/procfs 遥测机制，不等同于完整 syscall 追踪或通用沙箱。
