# v1 运行后设计复核

v1 的受控 fixture、安全边界、Marker 检测和 1 条 Base64 源到汇 witness 均真实通过，原始 Marker 泄露和静态决策变化均为 0。

但复核发现：`correlate_dynamic_evidence` 只检查“是否存在 witness”，没有验证 witness 的 `profile` 是否属于静态 Trigger Plan。该问题不会放行代码或改变静态决策，但会把“计划外动态证据”错误描述成“静动态已确认”。因此 v1 保留为校准父运行，不作为最终接受结果。

v2 收紧条件：只有 witness profile 属于 `plan.marker_profiles` 才能得到 `confirmed`；计划外 witness 只能得到 `observed`。新增一般化反例测试，不按样本 ID 或固定 marker ID 特判。
