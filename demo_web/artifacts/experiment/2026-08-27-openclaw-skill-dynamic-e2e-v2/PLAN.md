# PLAN：OpenClaw Skill 动态准入真实 E2E v2

## 1. v1 失败输入

v1 的合成 profile 没有 Docker `desktop-linux` context，安全与 Shell 两例都在容器创建前失败关闭。只读对照证明显式 `DOCKER_CONFIG` 后 Engine 29.7.2 可访问。v1 失败证据保持不变。

## 2. 单一修复

只向可信 Aegis install-policy 进程显式提供宿主 Docker CLI context 目录。边界保持：

- `passEnv=[]`，不复制 OpenClaw 宿主环境；
- Cisco 第三方扫描器仍使用独立合成 profile；
- Docker context 不挂载到目标容器；
- 目标容器仍为固定镜像、pull never、network none、非 root、只读根、无 capabilities；
- 不修改检测规则、决策阈值或 fixture。

## 3. 重跑用例与接受标准

使用新 run id 和全新 state/workspace/profile/temp/audit database，完整重跑：

1. 安全 Skill：静态 ALLOW、动态 ALLOW、OpenClaw 安装成功；
2. Shell Skill：静态 ALLOW、动态 `AEGIS_DYNAMIC_SHELL_SPAWN`、OpenClaw 安装前 BLOCK；
3. 无效动态模式：失败关闭、OpenClaw 安装前 BLOCK。

审计链、源码不变、隔离 workspace、用户默认 workspace 和 Docker 残留必须全部通过。

## 4. 声明边界

该修复解决可信 Docker CLI 的上下文发现，不向 Skill 增加权限。结果仍只覆盖自建 Python fixture 和当前 OpenClaw/Docker 版本，不扩展到任意第三方 Skill 或生产环境。
