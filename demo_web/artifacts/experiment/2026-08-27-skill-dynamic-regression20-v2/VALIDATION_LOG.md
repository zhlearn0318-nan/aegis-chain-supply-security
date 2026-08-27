# VALIDATION LOG

- 固定清单专项：`18 passed, 1 skipped`；跳过项为当前 Windows 账户不能创建符号链接。
- 真实 Docker：20 个样本 × 3 轮，共 60 次；`status=accepted`。
- 决策正确：60/60；必需规则命中：60/60。
- ALLOW / REVIEW / BLOCK：12 / 12 / 36。
- 良性误报、危险漏报、复核错配、跨轮不稳定：0 / 0 / 0 / 0。
- 遥测缺失、清理失败、容器残留：0 / 0 / 0。
- `process_os_system` 三轮均为 `AEGIS_DYNAMIC_SHELL_SPAWN / CRITICAL / BLOCK`。
- 完整后端：`422 passed, 1 skipped`，1 条第三方依赖弃用 warning。
- 运行环境误用记录：第一次完整后端命令使用缺少 FastAPI 的系统 Python，在测试收集阶段出现 17 个依赖错误；切换仓库固定 Python 3.13 运行时后完成正式回归，没有安装或升级依赖。
