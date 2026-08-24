# 安全说明

> 当前能力、未完成项和生产 NO-GO 判断见 [`CURRENT_STATUS.md`](CURRENT_STATUS.md)；本文件定义必须持续遵守的安全边界。

## 支持范围

本仓库是本地研究与比赛演示原型，不应直接部署到公网或生产政企环境。

## Fixture 使用边界

- `fixtures/` 中包含用于验证检测器的防御性风险样例；
- 不要执行标记为 `must never be executed` 的文件；
- 不要将第三方 Skill、数据集样本或未知脚本接入动态 fixture runner；
- Windows 协作式 runner 只允许执行 `demo_web/config/safe_dynamic_fixtures.json` 锁定的自建良性程序；
- Docker D2 后端只允许执行 `demo_web/config/docker_dynamic_backend.json` 锁定的单个安全 probe；
- `completed` 只表示机制自检通过，不代表第三方组件安全。

## Docker 动态后端边界

- 镜像必须用允许配置中的完整 digest 引用，必须 `pull=never`；
- 容器必须先 create 并通过真实 inspect 安全门，再允许 start；
- 必须保持 `network=none`、只读根、非 root、`cap-drop=ALL`、no-new-privileges 和资源限制；
- 只允许单个哈希锁定 fixture 文件只读挂载，不得挂载项目根、用户目录、凭据、Docker Socket 或宿主根；
- 清理只针对本轮 create 返回的精确 64 位 container ID，不得使用通配符或标签批量删除；
- D2 当前不得执行第三方 Skill、MCP Server、数据集样本或未知镜像；
- Docker/WSL2 仍共享宿主内核边界，本结果不证明不存在容器逃逸。

## 凭据管理

- 不要提交 `.env`、API Key、访问令牌、证书、私钥、数据库或浏览器会话；
- `AEGIS_ADMIN_TOKEN` 必须通过进程环境变量临时设置；
- 管理员令牌不得写入 URL、请求体、日志、SQLite、文档或截图；
- 如果凭据意外进入提交，应立即在对应平台吊销并轮换，而不只是删除文件。

## 项目自身供应链门

- 提交/发布前运行 `demo_web/audit_project_supply_chain.ps1 -WriteRepositoryArtifacts`；
- Python Web 子集与实际共享 Cisco/Aegis 运行时必须分别审计，不能只检查顶层 requirements；
- 直接依赖、包管理器和传递安全覆盖版本必须精确固定，安装必须核验锁文件哈希；
- `LICENSE`、`THIRD_PARTY_NOTICES.md` 和 `PROJECT_SBOM.cdx.json` 是发布必需制品；
- Secret 扫描只保留路径、行号和哈希指纹，不把疑似凭据复制进报告；
- Cisco `vulnerable-package` 若出现 pip-audit 错误、空 JSON 或与固定 oracle 不符，复现脚本必须失败闭锁，不能把空 Finding 当作 SAFE。

## 漏洞反馈

这是私有协作仓库。发现安全问题时，请在队内私下通知仓库维护者，不要在包含漏洞细节或凭据的公开 Issue 中披露。
