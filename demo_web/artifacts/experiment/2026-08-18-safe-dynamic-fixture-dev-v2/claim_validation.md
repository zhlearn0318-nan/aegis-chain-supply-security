# Claim validation

| Claim | Metric | Expected | Observed | Verdict |
|---|---|---:|---:|---|
| 三份自建 fixture 均完成 | fixtures_completed | 3/3 | 3/3 | supported |
| 预期动态机制均被观测 | expected checks | 7/7 | 7/7 | supported |
| 运行未触发越界策略 | policy violations | 0 | 0 | supported |
| 结果不保留原始测试 token | raw token leaks | 0 | 0 | supported |
| 不接触数据集或第三方样本 | protected samples read/executed | 0/0 | 0/0 | supported |
| 不改变准入决策 | decision changes | 0 | 0 | supported |

边界：这些结论只支持哈希锁定、自建 Python fixture 的协作式观测，不支持执行不可信 Skill、恶意样本或后代进程内部行为的安全声明。
