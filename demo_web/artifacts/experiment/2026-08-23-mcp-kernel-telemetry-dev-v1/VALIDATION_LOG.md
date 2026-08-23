# D3-B 正式运行与验证记录

## 环境与运行

- 固定镜像只读能力检查：strace 不可用。
- 未联网安装、未拉取镜像、未新增 capability。
- 正式状态：`completed`。
- 运行耗时：1.905 秒。
- 基础协议和安全门：66/66。
- 新增遥测门：16/16。
- 总门：82/82。

## 内核与进程证据

- inotify：`ACCESS`、`CLOSE_NOWRITE`、`OPEN`。
- procfs 父子关系：确认。
- procfs 目标文件 fd：确认，窗口内观察 47 次。
- 独立文件读取确认：1。
- strace 可用性：0，仅作为环境记录。

## 独立验证

- 项目标签容器残留：0。
- 初始 artifact manifest 9 项哈希不一致：0。
- run manifest 5 个源/配置文件哈希不一致：0。
- 原始 Marker 格式前缀命中：0。
- 原始 PID 字段命中：0。
- 原始命令行字段命中：0。
- 动态专项：51 passed。
- 完整后端：309 passed。

## 结论

- claim：`supported_on_controlled_fixture`。
- baseline relation：在 D3-A 上新增内核辅助旁证，父指标无退化。
- failure mode：`none`。
- next action：Skill 运行时闭包。
