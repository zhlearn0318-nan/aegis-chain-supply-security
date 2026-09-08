# M35 E04 鲁棒性修订 v2

## 1. v3 真实执行发现

v3 完成 48/48 个真实容器样本，风险变形非放行 24/24，预期规则 22/24（91.7%），但出现一个安全对照误阻断，因此整体未通过。

## 2. 三项根因

1. **Node 回环误报**：`net.connect(options)` 在 Node 内部会把参数正规化为数组再调用 `Socket.connect`。旧探针把数组序列化为 `[object Object]`，分类器误认为外部主机。
2. **Shell 路径漏证据**：Shell xtrace 已看到变量展开后的诱饵路径，但旧采集器只解析命令名，没有提取 `cat` 等读取命令的路径参数。
3. **Node 预期标签错误**：样本读取的是 `/etc/passwd`，实际正确规则为 `AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS`，而清单误写为仅适用于 `/workspace/decoys` 的 `AEGIS_DYNAMIC_DECOY_ACCESS`。

## 3. 最小修订

- 正确解析 Node `Socket.connect` 的数组化参数，保留回环豁免，外部目标仍产生证据；
- Shell 只从执行后的 xtrace 中提取受限文件读取命令的展开路径，不扫描未执行分支；
- 新建 v2 数据清单修正 Node 预期规则，Skill 文件内容与 v1 完全相同；
- 更新动态工具哈希锁，防止修订后的探针被静默替换。

v1/v2 基础设施失败和 v3 反例结果全部保留；修订结果写入新运行目录，不覆盖旧证据。
