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

- [ ] 获得创建临时、单仓库只读 GitHub Deploy Key 的明确授权。
- [ ] 生成一次性密钥，添加只读 deploy key，准备官方 GitHub SSH `known_hosts`。
- [ ] 将更新后的引导控制器和认证材料安全传入 guest。
- [ ] 冻结远端 `dynamic-audit-v1` 40 位 HEAD 并执行正式主运行。

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
- [ ] 吊销并删除 GitHub Deploy Key。
- [ ] 同步 `CURRENT_STATUS.md`、M5 计划、报告与 API/安全边界。
- [ ] 完整回归与 Secret 扫描通过。
- [ ] 独立提交并推送 P0-5 里程碑。
- [ ] 下一节点明确为 P1-1 静态扫描器隔离。
