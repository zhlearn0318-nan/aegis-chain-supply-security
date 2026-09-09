# M20 E01 静态检测组件消融实验合同 v5

> 状态：运行前冻结  
> 实验编号：`2026-09-06-m15-e01-static-ablation-v5`

## 1. v4 程序性失效

v4 的模型和阈值成功生成，但训练预检调用了会读取两个 split 标签文件的完整数据验证函数。validation 标签没有进入任何特征、模型、C 或阈值计算，但训练进程确实解析过该文件，因此“训练阶段不打开 validation ground truth”的程序性要求未满足。v4 产物保留为诊断材料，不承担正式锁箱结论。

## 2. v5 唯一变更

新增 `verify_scan_inputs`：它只读取指定 split 的 `intake_manifest.json`、`scan_manifest.jsonl` 和静态样本文件，禁止打开 `ground_truth`。v5 train 只校验 train；validation 直到模型、阈值、代码和烟雾结果冻结后才由 scan 阶段读取无标签输入，标签仅由最终 evaluate 命令打开一次。

v4 的逐来源留一、断点、高阈值尾部、模型、S0–S6、统计方法和接受门均不改变。由于合同身份变化，v4 模型和断点不复用，v5 重新训练。

## 3. 验收证据

训练回执必须明确 `validation_ground_truth_opened=false`；代码测试验证标签盲函数在没有 `ground_truth` 目录时仍可完成。任何训练阶段对 validation 标签路径的访问都使本版本再次失效。
