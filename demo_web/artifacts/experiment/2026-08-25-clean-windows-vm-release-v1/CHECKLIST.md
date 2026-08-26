# P0-5 真实 Windows VM 发布门检查表

## 已完成

- [x] 核对 Oracle VirtualBox 安装器签名、版本和 SHA-256。
- [x] 核对 Microsoft Windows 11 Enterprise Eval ISO 官方 SHA-256。
- [x] 创建具有 EFI Secure Boot、TPM 2.0 和独立 MachineGuid 的 VirtualBox guest。
- [x] 完成 Windows 11 Enterprise Eval 25H2 中文版真实安装。
- [x] VirtualBox Guest Additions `7.2.16 r174877` 达到桌面运行级别 3。
- [x] 使用受保护密码文件建立 `guestcontrol`，无密码命令行暴露。
- [x] guest 经无凭据宿主代理访问 GitHub，HEAD 返回 200。
- [x] 三份引导文件复制完成，宿主/来宾 SHA-256 逐一一致。
- [x] 新增临时只读 Deploy Key、严格 `known_hosts`、认证互斥和私钥删除合同。
- [x] PowerShell AST 解析通过；发布验收合同专项 `9 passed`。

## 当前执行

- [x] 获得创建临时、单仓库只读 GitHub Deploy Key 的明确授权。
- [x] 生成一次性密钥，添加只读 deploy key，核验官方 GitHub SSH `known_hosts`。
- [x] 将引导控制器和认证材料安全传入 guest；私钥 ACL 与 clone 后删除均验证通过。
- [x] 第一次主运行完成真实 clone 与负向 preflight，随后在运行时引导阶段失败；失败证据已固化且未冒充成功。
- [x] 修复原生 stderr 丢失，新增失败步骤 `.step.json`；AST、专项回归与行为探针通过。
- [x] 第二次主运行使用新工作区与新远端提交，确认 Windows Conda 根目录解释器布局是运行时引导失败根因；完整失败日志和 `.step.json` 已固化。
- [x] 实现统一 Conda/venv/POSIX 解释器解析并接入全部活跃入口；定向回归 `18/18` 通过。
- [x] 第三次主运行验证 Skill 安装和 MCP 环境/wheel 构建跨过解释器布局故障；确认 Conda `Library\bin` 未进入 PATH 导致 Cargo 不可发现，失败证据已固化。
- [x] 实现完整运行时 PATH 激活并接入引导、门禁、启动、测试、审计、复现脚本和后端扫描子进程；定向回归 `31/31` 通过。
- [x] PATH 修复完成完整回归与供应链门禁后，以提交 `6526843` 推送。
- [ ] 重启 VM 验证真实 Cargo，并在第四个全新工作目录执行正式主运行；2026-08-26 已延期，不作为比赛交付阻断项。

## 主运行验证

- [ ] VM attestation 通过且证据位于 clone 外部。
- [ ] 固定工具下载哈希/SRI 和运行时版本全部通过。
- [ ] 远端 ref、全新 clone、HEAD/origin/空工作区通过。
- [ ] 引导前负面 preflight 失败符合预期。
- [ ] 后端完整测试通过。
- [ ] 前端测试和生产构建通过。
- [ ] 项目自身供应链 gate 12/12 通过。
- [ ] Skill/MCP/依赖静态与机制动态四链 4/4 通过。
- [ ] JSON/Markdown/SBOM 7/7 导出通过。
- [ ] 依赖断网失败闭锁通过。
- [ ] Docker 能力通过或返回结构化 503 降级。
- [ ] 临时上传、动态工作区、容器、私钥和 tracked 改动残留为 0。

## 封口

- [ ] 从 guest 回收完整证据并验证 artifact manifest。
- [x] 吊销并删除 GitHub Deploy Key；GitHub 复核返回 404，本地临时认证三文件均不存在。
- [x] 同步 `CURRENT_STATUS.md`、M5 计划与本次范围决策；未改变 API 和安全边界。
- [ ] 完整回归与 Secret 扫描通过。
- [ ] 独立提交并推送 P0-5 里程碑。
- [x] 下一节点调整为比赛交付收敛；P1/P2 仅按得分贡献选择实施。

## 2026-08-26 范围决策

- [x] 保留 Attempt 1-3 的失败日志、步骤记录和根因分析。
- [x] 明确 Attempt 4 未执行，P0-5 未通过。
- [x] 将 P0-5 从内部发布阻断项调整为比赛交付的可选增强项。
- [x] 保持生产发布 `NO-GO`，不降低任何既有安全门。
