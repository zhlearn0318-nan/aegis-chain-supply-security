# M15 E02 真实 Skill 静态误报治理阶段结果

> 说明：真实合法 Skill 兼容性门已评测；恶意回归门尚未完成，因此当前候选不得直接进入产品。

## F0–F3 结果

| 系统 | 总判定 | 低权限 ALLOW | 低权限 BLOCK | 低权限 UNKNOWN | 低权限无必要非放行 | INFO 保留 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| F0 | {'ALLOW': 22, 'BLOCK': 5, 'REVIEW': 12, 'UNKNOWN': 1} | 66.7% | 4.2% | 4.2% | 7 | 0 |
| F1 | {'ALLOW': 24, 'BLOCK': 4, 'REVIEW': 11, 'UNKNOWN': 1} | 70.8% | 4.2% | 4.2% | 6 | 28 |
| F2 | {'ALLOW': 30, 'BLOCK': 4, 'REVIEW': 5, 'UNKNOWN': 1} | 83.3% | 4.2% | 4.2% | 3 | 38 |
| F3 | {'ALLOW': 31, 'BLOCK': 3, 'REVIEW': 5, 'UNKNOWN': 1} | 87.5% | 0.0% | 4.2% | 2 | 40 |

## 当前结论

- 低权限自动放行率：87.5%；
- 低权限直接阻断：0；
- 无必要 REVIEW/BLOCK 相对 F0 减少：71.4%；
- 被抑制发现仍以 INFO 留存：40 条；
- 完整高风险规则被降级：0 条；
- 真实 Skill 兼容性接受门：通过；
- 恶意回归门：待运行。只有回归下降不超过 2 个百分点后，才能决定是否接入 OpenClaw 正式准入。

## 高权限直接阻断解释

- `masb-045-dev-swarm-python`：完整链规则 AEGIS_REMOTE_FETCH_PIPE_SHELL；其余阻断规则 AEGIS_REMOTE_FETCH_PIPE_SHELL。
- `masb-061-godot-mcp-auto-launcher`：完整链规则 COMMAND_INJECTION_EVAL, COMMAND_INJECTION_JS_CHILD_PROCESS；其余阻断规则 COMMAND_INJECTION_EVAL, COMMAND_INJECTION_JS_CHILD_PROCESS, DATA_EXFIL_JS_FS_ACCESS。
- `openai-cloudflare-deploy`：完整链规则 AEGIS_PERSISTENCE_SERVICE_CREATE, AEGIS_REMOTE_FETCH_PIPE_SHELL；其余阻断规则 AEGIS_PERSISTENCE_SERVICE_CREATE, AEGIS_REMOTE_FETCH_PIPE_SHELL。
