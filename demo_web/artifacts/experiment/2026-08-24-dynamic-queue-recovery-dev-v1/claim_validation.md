# P0-2 Claim Validation

| 主张 | 证据 | 结论 |
| --- | --- | --- |
| 单主机任意时刻最多一个动态任务执行 | 双线程同时调用数据库认领函数，仅 FIFO 队首成功；受控 worker 记录峰值 1 | 支持 |
| 队列按提交顺序消费 | mechanism fixture 先执行，Skill closure 后执行，违反数 0 | 支持 |
| 重复提交不会制造任务风暴 | 活动重复和冷却重复均返回原 ID，数据库记录数不增加 | 支持 |
| 超限明确失败 | 等待上限 0 且已有 running 时，第二类任务返回 429 / `DYNAMIC_AUDIT_QUEUE_FULL` | 支持 |
| 重启后不存在不可解释中间态 | running 失败闭锁；queued 标记恢复并可再次原子认领 | 支持 |
| worker 异常不会永久 running | 未写终态时补写 `DYNAMIC_AUDIT_WORKER_DID_NOT_FINALIZE` | 支持 |
| 多实例生产队列可用 | 本轮未部署外部 broker/worker 或多实例服务 | 不主张，P2-2 验收 |

本轮没有修改检测规则、准入策略或动态 fixture，也没有运行第三方不可信样本。`container_residuals=0` 表示本轮队列验收没有创建容器，不是容器隔离能力的新证明。
