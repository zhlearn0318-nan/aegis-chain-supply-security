# OpenClaw E2E v1 计划

- run id：`2026-08-26-openclaw-e2e-v1`
- tier：`main/test`
- baseline：`0a0d1ec`
- 目标：真实 OpenClaw 安装调用、提交、阻断和失败关闭。

## 接受指标

- config_valid = true
- safe_install_success = true
- malicious_blocked = true
- malicious_residue = false
- review_fail_closed = true
- review_residue = false
- policy_path_failure_closed = true
- existing_workspace_residue = false
- backend_regression_passed = true

## 停止条件

- 覆盖用户现有 OpenClaw 配置或身份。
- 删除用户文件而非可恢复移动。
- 为通过测试关闭失败关闭策略。
- 升级全局 OpenClaw。
- 把 Beta 上游 ACL 失败写成通过。
