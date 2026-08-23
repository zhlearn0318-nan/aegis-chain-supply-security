# D3-B MCP 内核辅助遥测 v1 计划

## 1. 实验身份

- run id：`2026-08-23-mcp-kernel-telemetry-dev-v1`
- 分支：`dynamic-audit-v1`
- 层级：`auxiliary/dev`
- 父运行：`2026-08-23-mcp-protocol-marker-dev-v1`
- 父提交：`531bcdf`
- 目标：在不安装软件、不联网、不放宽容器权限的条件下，为真实 MCP 工具调用增加被测服务之外的文件与进程证据。

## 2. 路线选择

- 固定 Python 镜像实测 `strace=False`。
- 安全合同禁止联网安装、临时 apt、浮动依赖和新增 capability。
- 本轮使用 Python 标准库通过 libc 调用 Linux inotify，记录诱饵目录的 `OPEN/ACCESS/CLOSE_NOWRITE` 内核事件。
- 父进程并行读取服务进程的 `/proc/<pid>/status`、`cmdline`、`exe` 和 `fd`，只保留父子关系、参数数量、哈希和“目标文件描述符是否出现”，不保留原始 PID/命令行。
- 不宣称已实现 strace；它仅作为未来可固定带 strace 镜像时的可选增强。

## 3. 研究合同

- 研究问题：在 D3-A 协议和 Marker 结果不退化的前提下，内核 inotify 与 procfs 能否独立观察 MCP Server 进程实际打开并读取指定模拟公文？
- 零假设：inotify 未观察到目标文件打开/访问/关闭、procfs 未观察到服务进程持有目标 fd、父子关系不成立、基础 66 门任一退化或新增负面指标非 0。
- 备择假设：基础协议与安全门保持通过；inotify 同时观察目标文件 `OPEN/ACCESS/CLOSE_NOWRITE`；procfs 观察到服务 fd；父子关系成立；原始 PID、命令行和 Marker 均不进入证据。
- 最强替代解释：fixture 自己伪造“读取成功”字段。控制方式是内核事件与父进程 `/proc` 观察由客户端侧独立采集，服务端只执行文件读取，不能直接填写最终遥测门。

## 4. 必须指标

- 保持父实验全部协议、Docker、Marker 与负面指标；
- `telemetry_gates_passed` / `telemetry_gates_total`；
- `inotify_open_observed`、`inotify_access_observed`、`inotify_close_observed`（目标均 1）；
- `proc_parent_relation_confirmed`、`proc_fd_source_observed`（目标均 1）；
- `independent_file_read_confirmed`（目标 1）；
- `raw_pid_leaks`、`raw_cmdline_leaks`、`telemetry_errors`（目标均 0）；
- `strace_available` 记录为 0，不作为失败条件。

## 5. 实现与运行

- 最小：遥测门的单元反例与解析测试通过。
- solid：真实 Docker 中协议、基础安全、Marker、inotify、procfs 与清理门全部通过。
- 最大：未来使用固定的离线 strace/审计镜像做系统调用参数级复核，不在本轮范围。
- 运行预算：单 fixture，≤10 秒，CPU 0.5，内存 256 MiB，无 GPU、云、互联网和镜像拉取。
- 停止条件：全部正向门通过，负面指标为 0，完整后端回归通过。
- 放弃条件：必须新增 capability、特权、host PID、Docker Socket、联网安装或执行第三方样本。

## 6. 预期输出

- 沿用 MCP 实验的证据、指标、清单和日志文件；
- 新增内核遥测门、脱敏进程证据、inotify 事件名称与 procfs fd 命中布尔值；
- 新增 D3-B 实现报告。

## 7. 修订日志

| 时间 | 变更 | 原因 | 可比性影响 |
|---|---|---|---|
| 2026-08-23 | 首次预登记 | D3-A 已接受，进入独立遥测增强 | 保持父实验协议、Marker、镜像和安全合同 |
| 2026-08-23 | v1 正式接受 | inotify/procfs 遥测 16/16，总计 82/82 | 父实验正向与负面指标均未退化 |
