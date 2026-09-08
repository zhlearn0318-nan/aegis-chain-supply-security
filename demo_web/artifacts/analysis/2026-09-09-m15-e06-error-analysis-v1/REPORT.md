# E06 错误分析自动汇总

- 分析：114 条（漏报 60，误报/UNKNOWN 54）
- 明确归因：114/114（100.0%）
- 答辩案例：8 个
- 完成门：通过

## 前五类漏报原因

| 原因 | 数量 |
|---|---:|
| natural_language_sensitive_flow | 14 |
| contextual_instruction_paraphrase | 11 |
| implicit_execution_semantics | 8 |
| dependency_instruction_semantics | 7 |
| integrity_manipulation_semantics | 6 |

## 前五类误报原因

| 原因 | 数量 |
|---|---:|
| defensive_or_prohibitive_context | 32 |
| benign_conditional_workflow | 15 |
| materialization_or_scanner_failure | 4 |
| static_context_scope_error | 1 |
| label_boundary_or_quoted_context | 1 |

> 本报告是固定量表的单标注者事后诊断。它用于解释锁箱结果和设计新实验，不是重新计算的独立性能提升。
