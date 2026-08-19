# M1.2：扫描器适配器重构

## 做了什么

- 新建 `backend/adapters/process.py`，统一设置超时、UTF-8、缓存目录和 PATH；子进程只接受参数列表并明确使用 `shell=False`。
- 新建 Skill、MCP、依赖漏洞三个 adapter，分别负责命令构造、退出码判断、输出存在性和 JSON 完整性。
- `app.py` 只负责创建任务、调用 adapter、归一化、门禁和保存结果。
- 删除 `app.py` 中旧的进程执行、策略和四个归一化函数以及兼容别名。
- FastAPI 从弃用的 `@app.on_event("startup")` 迁移到 lifespan。

## 为什么这样拆

供应链安全系统不能把“外部工具执行失败”当成“没有风险”。Adapter 是故障边界：命令异常、超时、缺少文件、空输出和非法 JSON 都在进入业务层之前失败闭锁。以后升级 Cisco 版本、加入其他厂商工具或把执行迁入沙箱，只需要增加或替换 adapter。

## 验证结果

- 自动测试：27/27，通过且没有 FastAPI 弃用警告。
- 高风险 Skill：`BLOCK`，4 条 Finding，1 条 CRITICAL。
- MCP 混合对象：`BLOCK`，7 条 HIGH Finding。
- 旧版 urllib3：`BLOCK`，14 条 HIGH Finding。
- 三个制品 SHA-256 与既有记录一致，说明扫描输入没有变化。

## 下一步

M1.3 将门禁阈值、允许域名、敏感能力和禁用行为迁入 YAML 政企策略，并固定 `/api/v1` 契约。完成后再开始 SkillTrustBench 数据集适配。
