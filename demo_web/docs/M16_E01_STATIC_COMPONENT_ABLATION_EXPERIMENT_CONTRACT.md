# M16 E01 静态检测组件对照与消融实验合同

> 状态：运行前冻结
> 分支：`experiment-m15`
> 实验编号：`2026-09-05-m15-e01-static-ablation-v1`
> 父计划：`M15_FUTURE_EXPERIMENT_PLAN_CONTROL_ABLATION_ROBUSTNESS_PERFORMANCE.md`

## 1. 研究问题与假设

研究问题：Cisco、自研确定性规则、能力一致性、指令语义规则、本地 Qwen 和轻量文本模型分别给 Skill 准入带来多少恶意检出增量与良性放行损失？

- 零假设：加入能力一致性、语义证据、本地 Qwen 或轻量文本模型后，恶意非放行率没有可复现提升，或提升伴随不可接受的良性自动放行损失。
- 备择假设：至少一个自研组件能在相同样本和策略下带来可解释的配对增量；S5 相比当前 S4 在 validation 上满足预设召回与误报门槛。

本实验属于静态检测主实验。它不执行数据集中的脚本，不把模型判断直接升级为 BLOCK，也不使用 validation 调参。

## 2. 数据防火墙

数据固定为 MaliciousSkillBench 提交 `d4b42ce5766a6e0359c987cf59c1007cb3795a90` 的官方 Source-Disjoint 划分：

- train：7,513 条，用于模型拟合、分组交叉验证和阈值选择；
- validation：835 条，在代码、特征、模型超参数和阈值冻结后只完成一次评测；
- 已开封 test：1,384 条，只保留为历史/诊断结果，不参与本轮调参或主结论。

扫描器只读取不含标签的 `scan_manifest.jsonl` 和静态 `SKILL.md`。标签独立保存在 `ground_truth/labels.jsonl`，仅在扫描结果完全写入并校验哈希后由 evaluate 阶段连接。validation 的内容树和清单在运行前后必须保持 SHA-256 不变。

## 3. 比较系统

| 系统 | 唯一变化 | 目的 |
| --- | --- | --- |
| S0 | 仅 Cisco Finding | 厂商基线 |
| S1 | S0 + Aegis 确定性代码、数据流、上下文与控制规则 | 自研传统静态基线 |
| S2 | S1 + 声明—实现一致性 | 测量能力对齐贡献 |
| S3 | S1 + 确定性指令语义规则 | 测量规则语义贡献 |
| S4 | S1 + 能力一致性 + 语义规则 + 当前 Qwen 路由 | 当前 P0 完整对照 |
| S5 | S4 + TF-IDF/Logistic 轻量模型证据 | 候选改进主系统 |
| S6 | S5 关闭 Qwen | 判断 Qwen 的边际价值 |

所有系统复用同一次 Cisco 批量扫描和同一次 Aegis 全量 Finding 生成结果，再按 analyzer/rule 来源构造消融，避免重复扫描差异。除被消融组件外，策略、样本、版本和 UNKNOWN 处理保持一致。

## 4. 轻量模型冻结协议

- 特征：word 1–2 gram TF-IDF + char_wb 3–5 gram TF-IDF；
- 分类器：`LogisticRegression(class_weight="balanced")`；
- C 候选：0.25、0.5、1、2、4；
- 五折 `StratifiedGroupKFold`，以 `source_id` 分组，固定种子 20260905；
- 在 train 的 out-of-fold 概率上选择 C 和阈值；
- 阈值目标：良性误报率不超过5%时最大化恶意召回，随后按二分类宏 F1 和更高阈值打破平局；
- validation 不参与词表、参数、C 或阈值选择；
- 模型高风险预测只增加一个 MEDIUM/REVIEW Finding，不能直接产生 BLOCK。

模型文件必须同时保存训练配置、数据清单哈希、scikit-learn版本和模型SHA-256。若分组五折因来源/标签分布不可行，实验必须停止并建立新版本合同，不能静默退化为随机样本切分。

## 5. 主指标与接受门

所有系统报告：恶意非放行召回率、恶意 BLOCK 率、良性 ALLOW 率、良性 BLOCK 率、REVIEW/UNKNOWN 率、二分类宏 F1、平衡准确率和决策计数。

S5 相比 S4 的主接受门：

1. 恶意非放行召回提高至少8个百分点，或10,000次配对Bootstrap的95%置信区间下界大于0；
2. 良性自动ALLOW率下降不超过5个百分点；
3. 良性直接BLOCK率增加不超过1个百分点；
4. UNKNOWN率不高于S4；
5. validation完成运行恰好一次，输入树不变率100%。

同时报告配对精确 McNemar 检验。小于阈值或统计不显著的结果仍完整保存，并将结论记为 `refuted` 或 `inconclusive`。

## 6. 代码变更地图

| 路径 | 计划变更 | 风险控制 |
| --- | --- | --- |
| `tools/datasets/prepare_m15_e01_splits.py` | 生成 train/validation 标签隔离目录 | 拒绝覆盖；固定上游哈希；标签不进入扫描清单 |
| `tools/evaluation/run_m15_e01_static_ablation.py` | 训练、冻结、扫描、消融、统计和报告 | scan/evaluate分离；validation单次回执；可续跑 |
| `config/m15_e01_static_ablation_v1.json` | 固定全部比较条件与门槛 | 主运行后不可修改 |
| `artifacts/experiment/2026-09-05-m15-e01-static-ablation-v1/` | 保存合同、模型、日志、逐样本结果和指标 | 失败与负结果不删除 |

## 7. 运行与停止条件

先进行数据准备、train模型交叉验证和最多20条标签盲烟雾；仅当输出结构、Finding分组和标签防火墙通过后，才允许一次性运行835条validation。

出现下列任一情况立即停止：上游文件哈希不一致、validation标签进入扫描进程、validation已存在完成回执、输入树变化、比较系统改变多个非声明因素、模型或Qwen直接产生BLOCK、扫描异常被映射为ALLOW。

成功后进入 E02；失败时保留当前目录，说明属于数据、实现、环境还是方向问题，并建立新版本而不是覆盖 v1。
