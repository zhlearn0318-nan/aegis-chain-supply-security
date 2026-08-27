# CHECKLIST：Skill 安装前动态沙箱 dev-v1

## Planning

- [x] Skill-only、Docker、60–120 秒、动态影响准入范围确认
- [x] 宽松许可证约束确认
- [x] 开源候选与现有基线比较
- [x] 双后端路线和代码触点写入计划

## Implementation

- [x] 入口发现与路径边界
- [x] 固定 Python 行为采集启动器
- [x] Docker 安全合同与 inspect 门
- [x] 动态 Finding 与单调决策融合
- [x] Falco JSON 目标过滤与归一；真实 eBPF preflight 待 Docker ready
- [x] OpenClaw 安装准入联动

## Pilot / Smoke

- [x] 单元测试通过：专项 46；完整后端 417 passed, 1 skipped
- [ ] Docker Linux Engine ready
- [ ] 良性 fixture 真实运行
- [ ] 外连/诱饵/Shell/超时 fixture 真实运行
- [ ] 容器残留为 0
- [ ] Falco preflight 结论有真实证据

## Validation

- [x] dev 逻辑结果和指标完整；真实运行指标明确缺失
- [x] 逻辑回归错误放行为 0
- [x] 静态 BLOCK 动态执行为 0
- [x] 动态高危升级 BLOCK
- [x] 结论边界和下一动作记录

## Blocked

- [x] 2026-08-27：Docker Desktop 4.86.0 已安装，但 Linux Engine 在本次会话中未能启动；Falco 真实兼容性验证暂时阻塞。
