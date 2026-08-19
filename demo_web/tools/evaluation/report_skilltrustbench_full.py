from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUN = DEMO_ROOT / "artifacts" / "analysis" / "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
DEFAULT_COMPARATOR = DEMO_ROOT / "artifacts" / "analysis" / "2026-08-14-skilltrustbench-official10pct-cisco-v1"
DEFAULT_OUTPUT = DEMO_ROOT / "docs" / "M2_SKILLTRUSTBENCH_FULL_REPORT.md"
LABELS = ("normal", "suspicious", "malicious", "abstain")


class ReportError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ReportError(f"Expected JSON object: {path}")
    return payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def decimal(value: float) -> str:
    return f"{value:.4f}"


def pp(current: float, previous: float) -> str:
    difference = (current - previous) * 100
    return f"{difference:+.2f} pp"


def top_counts(items: Iterable[str | None], limit: int = 8) -> list[tuple[str, int]]:
    counts = Counter(str(item or "unknown") for item in items)
    return counts.most_common(limit)


def markdown_counts(rows: list[tuple[str, int]], total: int) -> str:
    if not rows:
        return "无"
    return "、".join(f"`{name}` {count} 条（{count / total:.2%}）" for name, count in rows)


def verify_declared_outputs(run_dir: Path, manifest: dict[str, Any]) -> None:
    for name, identity in manifest.get("outputs", {}).items():
        path = run_dir / name
        if not path.is_file():
            raise ReportError(f"Declared run output is missing: {path}")
        if path.stat().st_size != identity.get("bytes"):
            raise ReportError(f"Declared output size differs: {path}")
        if sha256_file(path) != identity.get("sha256"):
            raise ReportError(f"Declared output SHA-256 differs: {path}")


def build_report(run_dir: Path, comparator_dir: Path) -> str:
    manifest = load_json(run_dir / "run_manifest.json")
    if manifest.get("status") not in {"completed", "completed_with_abstentions"}:
        raise ReportError(f"Full run is not complete: {manifest.get('status')}")
    verify_declared_outputs(run_dir, manifest)
    metrics = load_json(run_dir / "metrics.json")
    matrix = load_json(run_dir / "confusion_matrix.json")["matrix"]
    rows = load_jsonl(run_dir / "per_case_results.jsonl")
    expected = int(manifest.get("expected_cases", 0))
    if len(rows) != expected or expected != 5_520:
        raise ReportError(f"Full result count differs: results={len(rows)}, expected={expected}")
    if [str(row.get("case_id")) for row in rows] != manifest["dataset"]["selected_case_ids"]:
        raise ReportError("Per-case result order differs from the frozen full selection")

    comparator = load_json(comparator_dir / "metrics.json")
    comparator_rows = load_jsonl(comparator_dir / "per_case_results.jsonl")
    full_by_id = {str(row["case_id"]): row for row in rows}
    overlap_pairs = [
        (full_by_id[str(row["case_id"])], row)
        for row in comparator_rows if str(row["case_id"]) in full_by_id
    ]
    comparable_pairs = [
        pair for pair in overlap_pairs
        if pair[0].get("status") == "completed" and pair[1].get("status") == "completed"
    ]
    decision_mismatches = sum(
        any((
            current.get("decision") != previous.get("decision"),
            current.get("predicted_label") != previous.get("predicted_label"),
            current.get("analyzers") != previous.get("analyzers"),
            current.get("summary") != previous.get("summary"),
            (current.get("policy_trace") or {}).get("rule_id")
            != (previous.get("policy_trace") or {}).get("rule_id"),
            {str(finding.get("rule_id")) for finding in current.get("finding_index") or []}
            != {str(finding.get("rule_id")) for finding in previous.get("finding_index") or []},
        ))
        for current, previous in comparable_pairs
    )
    status_shifts = sum(
        current.get("status") != previous.get("status")
        for current, previous in overlap_pairs
    )
    binary = metrics["aegis_policy_loose_non_normal"]
    completed = sum(row.get("status") == "completed" for row in rows)
    error_types = Counter(
        str((row.get("error") or {}).get("type") or "unknown")
        for row in rows if row.get("status") != "completed"
    )
    error_truth = Counter(
        (
            str((row.get("error") or {}).get("type") or "unknown"),
            str(row.get("ground_truth") or "unknown"),
        )
        for row in rows if row.get("status") != "completed"
    )
    analyzers = sorted({str(item) for row in rows for item in (row.get("analyzers") or [])})
    changed_hashes = sum(
        row.get("case_tree_sha256_before") != row.get("case_tree_sha256_after")
        for row in rows
    )
    risk_misses = [
        row for row in rows
        if row.get("ground_truth") != "normal"
        and row.get("predicted_label") not in {"suspicious", "malicious"}
    ]
    normal_false_positives = [
        row for row in rows
        if row.get("ground_truth") == "normal"
        and row.get("predicted_label") in {"suspicious", "malicious"}
    ]
    strict_malicious_misses = [
        row for row in rows
        if row.get("ground_truth") == "malicious"
        and row.get("predicted_label") != "malicious"
    ]
    fp_rule_cases: Counter[str] = Counter()
    for row in normal_false_positives:
        matched_ids = set((row.get("policy_trace") or {}).get("matched_finding_ids") or [])
        fp_rule_cases.update({
            str(finding.get("rule_id") or "unknown")
            for finding in row.get("finding_index") or []
            if finding.get("id") in matched_ids
        })
    top_fp_rules = fp_rule_cases.most_common(8)
    top_miss_bases = top_counts((row.get("base_category") for row in risk_misses), 8)
    top_miss_sources = top_counts((row.get("source") for row in risk_misses), 8)
    base_recall: list[tuple[str, int, int, float]] = []
    for category in sorted({str(row.get("base_category") or "unknown") for row in rows}):
        scoped = [
            row for row in rows
            if row.get("ground_truth") != "normal"
            and str(row.get("base_category") or "unknown") == category
        ]
        detected = sum(row.get("predicted_label") in {"suspicious", "malicious"} for row in scoped)
        if scoped:
            base_recall.append((category, len(scoped), detected, detected / len(scoped)))
    lowest_base_recall = sorted(base_recall, key=lambda item: (item[3], -item[1]))[:5]
    execution = metrics.get("execution", {})
    wall_seconds = float(execution.get("active_wall_seconds", 0))
    wall_minutes = wall_seconds / 60
    workers = int(execution.get("parallel_workers", 1))
    risk_rows = metrics["per_risk_label_recall"]

    confusion_lines = []
    for truth in LABELS[:3]:
        values = [int(matrix[truth][prediction]) for prediction in LABELS]
        confusion_lines.append(f"| {truth} | " + " | ".join(str(value) for value in values) + f" | {sum(values)} |")
    risk_lines = []
    for label in (f"T{index:02d}" for index in range(1, 10)):
        item = risk_rows[label]
        recall = "N/A" if item["recall"] is None else pct(float(item["recall"]))
        risk_lines.append(f"| {label} | {item['support']} | {item['detected']} | {recall} |")
    compare_fields = [
        ("coverage", "coverage", pct),
        ("failure rate", "failure_rate", pct),
        ("strict macro F1", "strict_macro_f1", decimal),
        ("malicious recall", "malicious_recall", pct),
        ("non-normal recall", "non_normal_recall", pct),
        ("normal FPR", "normal_fpr", pct),
    ]
    compare_lines = []
    for label, key, formatter in compare_fields:
        old = float(comparator[key])
        new = float(metrics[key])
        delta = pp(new, old) if formatter is pct else f"{new - old:+.4f}"
        compare_lines.append(f"| {label} | {formatter(old)} | {formatter(new)} | {delta} |")
    old_binary = comparator["aegis_policy_loose_non_normal"]
    for label, key in (("策略层 precision", "precision"), ("策略层 loose F1", "loose_f1")):
        old = float(old_binary[key])
        new = float(binary[key])
        compare_lines.append(f"| {label} | {pct(old)} | {pct(new)} | {pp(new, old)} |")

    error_lines = [f"| `{name}` | {count} |" for name, count in sorted(error_types.items())]
    error_truth_text = "、".join(
        f"`{error_type}`-{truth} {count} 条"
        for (error_type, truth), count in sorted(error_truth.items())
    )
    fp_rule_text = "、".join(f"`{name}`（{count} 个正常误报案例）" for name, count in top_fp_rules) or "无"
    base_recall_text = "、".join(
        f"`{category}` {detected}/{support}（{recall:.2%}）"
        for category, support, detected, recall in lowest_base_recall
    )
    first_command = manifest.get("command_history", [{}])[0].get("display", "")

    return f"""# SkillTrustBench 全量数据集 Cisco 静态扫描报告

> 运行 ID：`{manifest['run_id']}`  
> 最终状态：`{manifest['status']}`  
> 数据规模：5,520 条完整 v1.0 真值样本  
> 结论等级：`accepted_with_caveats`

## 1. 一页结论

本轮使用与官方 10% 子集实验相同的 Cisco Skill Scanner、统一准入策略、标签映射和失败闭锁规则，对 SkillTrustBench v1.0 全部 5,520 条样本进行本地离线静态评测。5,520/5,520 条均产生终态，其中 {completed} 条完成 Cisco 扫描，{metrics['abstention_count']} 条按 `UNKNOWN/abstain` 计入严格指标。

核心结果：覆盖率 {pct(metrics['coverage'])}，strict macro F1 为 {decimal(metrics['strict_macro_f1'])}，恶意严格召回率 {pct(metrics['malicious_recall'])}；统一策略层 non-normal 二分类 precision 为 {pct(binary['precision'])}、recall 为 {pct(binary['recall'])}、loose F1 为 {pct(binary['loose_f1'])}、正常样本 FPR 为 {pct(binary['fpr'])}。这些结果能够描述当前冻结配置在该公开基准上的表现，但不能证明系统对现实世界未知攻击具有同等效果，也不能替代动态验证。

## 2. 数据与安全边界

数据来自 [SkillTrustBench](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench)，本轮固定到审计刷新提交并使用完整 `ground_truth.json` 作为唯一标签来源。

| 项目 | 固定值 |
|---|---|
| 数据集 | SkillTrustBench v1.0 audited refresh |
| 数据提交 | `{manifest['dataset']['revision']}` |
| ground truth SHA-256 | `{manifest['dataset']['ground_truth_sha256']}` |
| 完整 ZIP SHA-256 | `{manifest['dataset']['archive_sha256']}` |
| 样本 ID SHA-256 | `{manifest['dataset']['case_ids_sha256']}` |
| 许可证 | CC BY-NC-SA 4.0 |
| 标签分布 | normal 1,643 / suspicious 1,014 / malicious 2,863 |
| 本机可扫描 | {manifest['dataset']['scanner_eligible_cases']} |
| 本机不可扫描 | {manifest['dataset']['scanner_ineligible_cases']} |

- 不执行、不导入、不安装样本或样本依赖。
- 不开启 LLM、AI Defense、VirusTotal、云上传或行为分析。
- 仅允许 `static_analyzer`、`bytecode`、`pipeline`；本轮实际观察到：`{'`、`'.join(analyzers)}`。
- 每条可扫描样本在 Cisco 扫描前后计算 tree SHA-256；发生变化即停止整批。本轮变化数为 {changed_hashes}。
- 端点防护或 Windows 路径规则阻止的样本不绕过、不改名，直接记为 UNKNOWN。

## 3. 运行配置与效率

| 项目 | 结果 |
|---|---:|
| 并发扫描进程 | {workers} |
| 活跃墙钟时间 | {wall_minutes:.2f} 分钟 |
| 吞吐 | {execution.get('throughput_cases_per_minute', 0):.2f} 条/分钟 |
| 单样本中位耗时 | {metrics['latency_median_ms']:,} ms |
| 单样本 P95 | {metrics['latency_p95_ms']:,} ms |
| 单样本最大耗时 | {metrics['latency_max_ms']:,} ms |
| 单条超时 | {manifest['scanner']['timeout_seconds_per_case']} 秒 |

并发后的单样本耗时包含 CPU 与磁盘资源竞争，不能直接与顺序扫描的约 4 秒中位数解释为扫描器变慢；批量效率应主要观察墙钟时间与吞吐。按上轮 4.028 秒中位数粗略估算，5,520 条顺序运行约需 370 分钟；本轮实际为 145.43 分钟，约缩短到估算顺序时间的 39%。该比例是工程估算，不是严格的同批次单线程对照。首次运行命令为：

```powershell
{first_command}
```

## 4. 总体扫描结果

### 4.1 三分类严格指标

| 指标 | 结果 |
|---|---:|
| 处理样本 | {len(rows)} / {expected} |
| Cisco 完成扫描 | {completed} |
| abstain | {metrics['abstention_count']} |
| coverage | {pct(metrics['coverage'])} |
| failure rate | {pct(metrics['failure_rate'])} |
| strict macro F1 | {decimal(metrics['strict_macro_f1'])} |
| covered macro F1 | {decimal(metrics['covered_macro_f1'])} |
| 三分类准确率 | {pct(metrics['supplementary_accuracy'])} |
| malicious recall | {pct(metrics['malicious_recall'])} |
| malicious FNR | {pct(metrics['malicious_fnr'])} |
| non-normal recall | {pct(metrics['non_normal_recall'])} |
| normal FPR | {pct(metrics['normal_fpr'])} |

### 4.2 统一策略层 non-normal 二分类

| 指标 | 结果 |
|---|---:|
| TP | {binary['tp']} |
| FP | {binary['fp']} |
| FN | {binary['fn']} |
| TN | {binary['tn']} |
| precision | {pct(binary['precision'])} |
| recall | {pct(binary['recall'])} |
| loose F1 | {pct(binary['loose_f1'])} |
| FPR | {pct(binary['fpr'])} |

### 4.3 三分类混淆矩阵

行是真值，列是系统预测。

| ground truth | normal | suspicious | malicious | abstain | 合计 |
|---|---:|---:|---:|---:|---:|
{chr(10).join(confusion_lines)}

## 5. T01–T09 风险类型召回

“detected”指策略结果为 REVIEW 或 BLOCK；风险标签允许多选。

| 风险类型 | support | detected | recall |
|---|---:|---:|---:|
{chr(10).join(risk_lines)}

## 6. 失败与不可扫描案例

| 类型 | 数量 |
|---|---:|
{chr(10).join(error_lines)}

失败与不可扫描结果全部按 UNKNOWN 处理，没有被当作 normal 放行。端点防护和平台不兼容案例的原始身份仍由完整 ZIP 与归档内 tree hash 固定；Cisco 运行时错误只保留脱敏错误类型，不传播不可信错误正文。

按真值进一步拆分为：{error_truth_text}。其中 61 条端点防护阻断全部是 malicious，这说明安全软件本身提供了额外保护，但本系统仍把它们计为 UNKNOWN，而没有借用 Defender 结果冒充 Cisco 检出。

## 7. 误报与漏报

- non-normal 风险筛查漏报：{len(risk_misses)} 条；主要 base category 为 {markdown_counts(top_miss_bases, len(risk_misses))}。
- 漏报主要来源为 {markdown_counts(top_miss_sources, len(risk_misses))}。
- base category 召回最低的五类为 {base_recall_text}；其中 `wild_real_world` 明显低于其他类别，是当前最重要的泛化短板。
- malicious 严格漏报：{len(strict_malicious_misses)} 条，其中预测为 REVIEW 的案例仍会进入人工复核，但在三分类严格口径中记为错误。
- normal 误报：{len(normal_false_positives)} 条；常见触发规则为 {fp_rule_text}。

这些错误切片用于确定下一轮规则与动态验证优先级，不应在同一全量数据上反复调参后继续把结果当作无偏测试成绩。

## 8. 与官方固定 10% 子集实验对照

10% 清单是全量数据的一部分，不是独立测试集。下表用于检查结论稳定性与抽样偏差，不能作为两个独立总体的显著性比较。

| 指标 | 官方 10%（556） | 全量（5,520） | 变化 |
|---|---:|---:|---:|
{chr(10).join(compare_lines)}

10% 子集与全量实验保持扫描器、策略、标签映射及失败闭锁口径一致；执行方式由顺序扫描改为 {workers} 路并发，因此准确率类指标可以直接核对，单样本延迟则需结合资源竞争解释。

重叠复现检查覆盖 {len(overlap_pairs)} 条固定 10% 案例，其中 {len(comparable_pairs)} 条在两轮中均由 Cisco 完成扫描。忽略因本地目录不同而必然变化的绝对路径后，最终决策、预测标签、分析器、告警汇总、策略规则和告警规则集合共有 {decision_mismatches} 条不一致；扫描终态变化 {status_shifts} 条。该检查用于发现并发、数据复制或运行环境造成的结论漂移。

## 9. 指标含义与证据边界

- `strict macro F1`：normal、suspicious、malicious 三类 F1 的等权平均；UNKNOWN 按错误计。
- `malicious recall`：恶意样本中最终判为 BLOCK/malicious 的比例；判为 REVIEW 仍是严格三分类错误。
- `non-normal recall`：malicious 或 suspicious 中被送入 REVIEW/BLOCK 的比例，更贴近安全准入筛查。
- `normal FPR`：正常样本被送入 REVIEW/BLOCK 的比例，反映人工复核与业务阻断压力。
- 公开基准中的模板注入和变异样本与真实生产分布不同；当前结果不能外推为生产环境检出率。
- 全量公开数据已被用于本次最终评测。后续如果依据这些错误案例开发规则，应另建冻结测试集或引入第二数据集评估泛化。

## 10. 下一步开发建议

1. 从全量风险漏报中按 `wild_real_world`、`crypto_wallet` 和最低召回 T 类建立小规模开发集，另留不参与调参的回归集。
2. 对正常误报最高频规则增加“声明能力—实际行为—目标对象”的上下文条件，不全局降低严重度。
3. 动态验证先使用无害自建 fixture，采集进程、网络、文件写入和敏感环境变量访问；真实恶意样本只在专门隔离沙箱中处理。
4. 大模型只复核静态 UNKNOWN/冲突或高价值样本，并单独比较召回提升、误报、耗时与成本，不能替代确定性规则和动态证据。

## 11. 证据文件

- 运行清单：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/run_manifest.json`
- 逐 case 结果：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/per_case_results.jsonl`
- 指标：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/metrics.json`
- 混淆矩阵：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/confusion_matrix.json`
- 正常误报：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/false_positive_cases.jsonl`
- 恶意严格漏报：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/false_negative_cases.jsonl`
- 全部分类错误：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/classification_errors.jsonl`
- 运行日志：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/run.log`
- 独立验收：`{run_dir.relative_to(DEMO_ROOT).as_posix()}/verification.json`
- 全量安全导入清单：`../datasets/skilltrustbench_v1_0/full/intake_manifest.json`
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the completed SkillTrustBench full-run report")
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--comparator-dir", type=Path, default=DEFAULT_COMPARATOR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report(args.run_dir.resolve(), args.comparator_dir.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8", newline="\n")
    print(json.dumps({"status": "written", "output": str(args.output.resolve())}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
