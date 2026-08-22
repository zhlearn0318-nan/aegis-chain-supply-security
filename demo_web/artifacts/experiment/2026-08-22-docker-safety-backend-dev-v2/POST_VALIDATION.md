# D2 v2 运行后验证

- Docker Desktop：4.86.0；Linux Engine：29.7.2；API：1.55；内核：WSL2 6.18.33.2。
- 镜像身份门：4/4；create 后 inspect 配置门：24/24；运行时行为门：12/12；合计 40/40。
- 运行用户：UID/GID 65532；CapEff 为全 0；NoNewPrivs=1；Seccomp=2。
- 只读根写入：拒绝；只读 fixture 写入：拒绝；`/workspace` 和 `/tmp` tmpfs 写入：成功。
- 网络接口：仅 `lo`；Docker NetworkMode：`none`；镜像拉取：0。
- 成功运行容器已删除；独立按 `aegis.dynamic.backend` 标签查询：0 条残留。
- 模拟启动超时路径：仍使用本轮精确 container ID 强制删除并验证不存在。
- Docker 专项测试：`26 passed`；后端完整测试：`296 passed`。
- 第三方/回归样本读取与执行、互联网、GPU、云和静态决策变化均为 0。
- 声明边界：当前证据不能证明不存在容器/内核逃逸，也不能证明第三方样本安全。
