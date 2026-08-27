# OpenClaw Skill 动态准入 E2E v1 失败分析

## 现象

- 3 个安装用例通过 2 个，但安全 Skill 未能安装；
- 安全和 Shell 两例均记录 `AEGIS_DYNAMIC_TELEMETRY_INCOMPLETE` 与 `AEGIS_DYNAMIC_EXECUTION_INCONCLUSIVE`；
- 无效动态模式正确失败关闭；
- 审计链、输入不变性、隔离 workspace、阻断无残留和容器清理均通过。

## 根因

验收工具为 OpenClaw 建立了合成 `USERPROFILE`。install policy 继承该隔离身份后，Docker CLI 使用：

`<isolated-profile>/.docker/contexts/...`

解析 `desktop-linux`，但该合成 profile 没有 Docker Desktop context 元数据，因此在容器创建前失败。目标 Skill 没有执行，系统按 REVIEW→block 兼容策略失败关闭。

只读对照已经确认：

- 合成 profile、没有 `DOCKER_CONFIG`：`context "desktop-linux": context not found`；
- 同一 profile、显式 `DOCKER_CONFIG=<host-profile>/.docker`：Engine 返回 `29.7.2`。

## 修复方案

v2 只向可信 Aegis install-policy 进程显式提供 Docker CLI context 目录。Cisco 第三方扫描器仍由 `build_scanner_environment` 创建独立合成 profile；目标 Skill 容器仍只有 `/skill` 与 `/aegis_tool` 两个只读挂载，不获得宿主 Docker 配置、用户目录或 Docker Socket。

## 决策

v1 保留为失败证据，不修改结果文件冒充成功。v2 使用新 run id、全新 state/workspace/profile/temp 和审计数据库重新运行全部用例。
