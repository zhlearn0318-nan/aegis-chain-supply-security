# OpenClaw Install Policy v1 检查表

## 合同

- [x] 冻结 protocol v1 输入输出合同。
- [x] 冻结 ALLOW/REVIEW/BLOCK/UNKNOWN 映射。
- [x] 明确 plugin 在 v1 中失败关闭。
- [x] 明确不修改静态规则和密封回归结果。

## 实现

- [x] 协议请求校验。
- [x] 有界文件树哈希与链接拒绝。
- [x] 同步 Skill 扫描核心复用。
- [x] Finding 限长、限量、严重度优先和路径脱敏。
- [x] CLI 单 JSON UTF-8 stdout。
- [x] OpenClaw 配置示例。

## 测试

- [x] allow/warn/block/unknown 映射测试。
- [x] 非法 JSON、协议、目标、路径测试。
- [x] 扫描超时与异常失败关闭测试。
- [x] 扫描期间源码变化阻断测试。
- [x] 真实安全/恶意内置 Skill 冒烟测试。
- [x] 完整后端回归测试：383 passed。

## 证据

- [x] 记录精确命令、环境和代码版本。
- [x] 保存测试与真实冒烟结果。
- [x] 输出 evaluation summary 和结论。
- [x] 明确下一步 OpenClaw 真实安装验证。
