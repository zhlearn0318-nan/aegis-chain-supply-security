from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters import ProcessRunner, SkillScannerAdapter  # noqa: E402
from backend.dynamic_audit.docker_backend import _docker_prefix, discover_docker_cli, run_docker_cli  # noqa: E402
from backend.dynamic_audit.skill_sandbox_multiruntime import (  # noqa: E402
    BACKEND_ID,
    CONFIG_PATH,
    load_multiruntime_config,
    run_multiruntime_entrypoint,
)
from backend.policy import DEFAULT_POLICY_PATH, evaluate_findings, load_policy, summarize  # noqa: E402
from backend.skill_static_pipeline import run_skill_static_pipeline  # noqa: E402
from tools.datasets.prepare_third_party_skill_dynamic_pairs import tree_sha256  # noqa: E402


RUN_ID = "2026-08-31-third-party-skill-dynamic-pairs-main-v1"
DATA_ROOT = REPRODUCTION_ROOT / "datasets" / "third_party_skill_dynamic_pairs_v1"
CONTRACT_PATH = DEMO_ROOT / "config" / "third_party_dynamic_pairs_eval_v1.json"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "analysis" / RUN_ID
EVENT_TYPES = {
    "decoy_access": {"decoy.read", "marker.read"},
    "shell_spawn": {"os.system", "process.spawn", "subprocess.popen"},
    "sensitive_path": {"file.open", "open"},
    "external_network": {"network.connect", "socket.connect", "dns.resolve"},
    "adversarial_timeout": {"runtime.timeout"},
}
DECISION_RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2, "UNKNOWN": 2}


class EvaluationError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvaluationError(f"Expected JSON object: {path}")
    return payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not all(isinstance(record, dict) for record in records):
        raise EvaluationError(f"Expected JSON objects: {path}")
    return records


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def compact_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "rule_id": str(item.get("rule_id") or ""),
            "severity": str(item.get("severity") or "UNKNOWN"),
            "category": str(item.get("category") or ""),
            "analyzer": str(item.get("analyzer") or ""),
            "location": item.get("location"),
            "evidence": str(item.get("evidence") or "")[:400],
        }
        for item in findings
    ]


def verify_dataset() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    manifest_path = DATA_ROOT / "manifest.jsonl"
    source_lock = load_json(DATA_ROOT / "source_lock.json")
    contract = load_json(CONTRACT_PATH)
    if source_lock.get("manifest_sha256") != sha256_file(manifest_path):
        raise EvaluationError("Dataset manifest identity mismatch")
    records = load_jsonl(manifest_path)
    counts = contract.get("case_counts") or {}
    originals = [row for row in records if row.get("variant") == "original"]
    risks = [row for row in records if row.get("variant") == "controlled_risk_twin"]
    if len(records) != counts.get("total") or len(originals) != counts.get("original") or len(risks) != counts.get("controlled_risk_twin"):
        raise EvaluationError("Dataset counts differ from the frozen contract")
    if len({str(row.get("case_id")) for row in records}) != len(records):
        raise EvaluationError("Duplicate case ID")
    for record in records:
        case_root = (DATA_ROOT / str(record["local_path"])).resolve(strict=True)
        case_root.relative_to((DATA_ROOT / "cases").resolve(strict=True))
        if tree_sha256(case_root) != record.get("case_tree_sha256"):
            raise EvaluationError(f"Case tree drift before run: {record['case_id']}")
        source_script = case_root / str(record.get("original_entrypoint") or record["entrypoint"])
        if sha256_file(source_script) != record.get("source_script_sha256"):
            raise EvaluationError(f"Original source script drift: {record['case_id']}")
    return records, source_lock, contract


def static_scan(adapter: SkillScannerAdapter, policy: Any, record: dict[str, Any]) -> dict[str, Any]:
    case_root = (DATA_ROOT / str(record["local_path"])).resolve(strict=True)
    before = tree_sha256(case_root)
    started = time.perf_counter()
    try:
        pipeline = run_skill_static_pipeline(case_root, adapter, semantic_provider=None)
        findings = pipeline["findings"]
        evaluation = evaluate_findings(findings, policy)
        status = "completed"
        decision = evaluation.decision.value
        trace = evaluation.trace.model_dump(mode="json")
        error = None
    except Exception as exc:  # fail closed while retaining only trusted error metadata
        findings = []
        status = "failed"
        decision = "UNKNOWN"
        trace = {"rule_id": "SCAN_EXECUTION_FAILED", "fail_closed": True}
        error = {"type": type(exc).__name__}
        pipeline = {"analyzers": [], "logs": []}
    after = tree_sha256(case_root)
    if after != before:
        raise EvaluationError(f"Static scan mutated case: {record['case_id']}")
    return {
        "case_id": record["case_id"],
        "status": status,
        "decision": decision,
        "duration_ms": max(1, round((time.perf_counter() - started) * 1000)),
        "summary": summarize(findings),
        "policy_trace": trace,
        "analyzers": pipeline.get("analyzers") or [],
        "logs": pipeline.get("logs") or [],
        "findings": compact_findings(findings),
        "case_tree_sha256_before": before,
        "case_tree_sha256_after": after,
        "error": error,
    }


def dynamic_scan(config: Any, record: dict[str, Any], timeout_seconds: float, output: Path) -> dict[str, Any]:
    case_root = (DATA_ROOT / str(record["local_path"])).resolve(strict=True)
    before = tree_sha256(case_root)
    result = run_multiruntime_entrypoint(
        config,
        case_root,
        str(record["entrypoint"]),
        str(record["runtime"]),
        timeout_seconds,
        tuple(str(value) for value in record.get("argv") or []),
    )
    after = tree_sha256(case_root)
    if after != before:
        raise EvaluationError(f"Dynamic scan mutated read-only case: {record['case_id']}")
    write_json(output / "dynamic_results" / f"{record['case_id']}.json", result)
    evaluation = result.get("evaluation") or {}
    runner = result.get("runner") or {}
    events = runner.get("events") or []
    rule_ids = sorted({str(item.get("rule_id") or "") for item in evaluation.get("findings") or []})
    expected_rule = record.get("expected_rule_id")
    expected_types = EVENT_TYPES.get(str(record.get("risk_type") or ""), set())
    expected_event_in_adversarial = any(
        isinstance(event, dict)
        and str(event.get("type") or "").casefold() in expected_types
        and str(event.get("round") or "") == "adversarial"
        for event in events
    ) if expected_types else None
    rounds = [item.get("id") for item in runner.get("rounds") or [] if isinstance(item, dict)]
    return {
        "case_id": record["case_id"],
        "decision": evaluation.get("decision"),
        "status": evaluation.get("status"),
        "duration_ms": result.get("duration_ms"),
        "success": result.get("success"),
        "error": result.get("error"),
        "rule_ids": rule_ids,
        "expected_rule_detected": expected_rule in rule_ids if expected_rule else None,
        "expected_event_in_adversarial": expected_event_in_adversarial,
        "round_ids": rounds,
        "event_count": len(events),
        "image_gates_all": bool(result.get("image_gates")) and all((result.get("image_gates") or {}).values()),
        "inspect_gates_all": bool(result.get("inspect_gates")) and all((result.get("inspect_gates") or {}).values()),
        "cleanup_verified": (result.get("cleanup") or {}).get("removed") is True and (result.get("cleanup") or {}).get("residual") is False,
        "argv_attestation": result.get("argv_attestation"),
        "case_tree_sha256_before": before,
        "case_tree_sha256_after": after,
    }


def compute_metrics(records: list[dict[str, Any]], static_results: list[dict[str, Any]], dynamic_results: list[dict[str, Any]]) -> dict[str, Any]:
    static_by_id = {row["case_id"]: row for row in static_results}
    dynamic_by_id = {row["case_id"]: row for row in dynamic_results}
    originals = [row for row in records if row["variant"] == "original"]
    risks = [row for row in records if row["variant"] == "controlled_risk_twin"]
    expected_detected = sum(dynamic_by_id[row["case_id"]]["expected_rule_detected"] is True for row in risks)
    risk_non_allow = sum(dynamic_by_id[row["case_id"]]["decision"] in {"REVIEW", "BLOCK"} for row in risks)
    original_allow = sum(dynamic_by_id[row["case_id"]]["decision"] == "ALLOW" for row in originals)
    decision_lifts = sum(
        DECISION_RANK.get(str(dynamic_by_id[row["case_id"]]["decision"]), 2)
        > DECISION_RANK.get(str(static_by_id[row["case_id"]]["decision"]), 2)
        for row in records
    )
    per_risk: dict[str, Any] = {}
    for risk_type in sorted({str(row["risk_type"]) for row in risks}):
        subset = [row for row in risks if row["risk_type"] == risk_type]
        per_risk[risk_type] = {
            "support": len(subset),
            "expected_rule_detected": sum(dynamic_by_id[row["case_id"]]["expected_rule_detected"] is True for row in subset),
            "non_allow": sum(dynamic_by_id[row["case_id"]]["decision"] in {"REVIEW", "BLOCK"} for row in subset),
            "adversarial_round_event": sum(dynamic_by_id[row["case_id"]]["expected_event_in_adversarial"] is True for row in subset),
        }
    all_dynamic = list(dynamic_by_id.values())
    durations = [int(row.get("duration_ms") or 0) for row in all_dynamic]
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "cases": len(records),
        "container_script_invocations": len(records) * 3,
        "static_decisions": dict(sorted(Counter(str(row["decision"]) for row in static_results).items())),
        "dynamic_decisions": dict(sorted(Counter(str(row["decision"]) for row in dynamic_results).items())),
        "expected_dynamic_rule_recall": expected_detected / len(risks),
        "controlled_risk_non_allow_recall": risk_non_allow / len(risks),
        "original_allow_rate": original_allow / len(originals),
        "original_false_positive_non_allow_rate": 1 - original_allow / len(originals),
        "adversarial_trigger_attestation_rate": sum(row["expected_event_in_adversarial"] is True for row in (dynamic_by_id[item["case_id"]] for item in risks)) / len(risks),
        "decision_lift_cases": decision_lifts,
        "decision_lift_rate": decision_lifts / len(records),
        "three_round_attestation_rate": sum(row["round_ids"] == ["typical", "edge", "adversarial"] for row in all_dynamic) / len(all_dynamic),
        "container_security_gate_rate": sum(row["image_gates_all"] and row["inspect_gates_all"] for row in all_dynamic) / len(all_dynamic),
        "cleanup_verification_rate": sum(row["cleanup_verified"] for row in all_dynamic) / len(all_dynamic),
        "case_tree_immutability_rate": sum(row["case_tree_sha256_before"] == row["case_tree_sha256_after"] for row in all_dynamic) / len(all_dynamic),
        "infrastructure_success_rate": sum(row["success"] is True for row in all_dynamic) / len(all_dynamic),
        "latency_ms": {
            "median": round(statistics.median(durations)) if durations else 0,
            "mean": round(statistics.fmean(durations)) if durations else 0,
            "max": max(durations, default=0),
        },
        "per_risk_type": per_risk,
    }


def acceptance(metrics: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    thresholds = contract["acceptance_thresholds"]
    checks = {
        "expected_dynamic_rule_recall": metrics["expected_dynamic_rule_recall"] >= thresholds["expected_dynamic_rule_recall_min"],
        "controlled_risk_non_allow_recall": metrics["controlled_risk_non_allow_recall"] >= thresholds["controlled_risk_non_allow_recall_min"],
        "original_allow_rate": metrics["original_allow_rate"] >= thresholds["original_allow_rate_min"],
        "three_round_attestation_rate": metrics["three_round_attestation_rate"] == thresholds["three_round_attestation_rate"],
        "container_security_gate_rate": metrics["container_security_gate_rate"] == thresholds["container_security_gate_rate"],
        "cleanup_verification_rate": metrics["cleanup_verification_rate"] == thresholds["cleanup_verification_rate"],
        "case_tree_immutability_rate": metrics["case_tree_immutability_rate"] == thresholds["case_tree_immutability_rate"],
    }
    return {"passed": all(checks.values()), "checks": checks}


def build_report(records: list[dict[str, Any]], static_results: list[dict[str, Any]], dynamic_results: list[dict[str, Any]], metrics: dict[str, Any], result: dict[str, Any]) -> str:
    static_by_id = {row["case_id"]: row for row in static_results}
    dynamic_by_id = {row["case_id"]: row for row in dynamic_results}
    lines = [
        "# 真实第三方 Skill 容器动态审计效果报告",
        "",
        f"- 主实验结论：**{'PASS' if result['acceptance']['passed'] else 'FAIL'}**",
        f"- 真实来源原型：6 个（OpenAI 5 个、Anthropic 1 个），均为 Apache-2.0",
        "- 配对样本：6 个原始样本 + 30 个受控风险孪生样本 = 36 个 Skill 包",
        f"- 实际容器脚本调用：{metrics['container_script_invocations']} 次（每包 typical / edge / adversarial 三轮）",
        "- 安全边界：已知恶意第三方 Skill 未执行；所有执行均断网、只读挂载、非 root、能力清空并限制资源",
        "",
        "## 核心指标",
        "",
        "| 指标 | 结果 | 含义 |",
        "|---|---:|---|",
        f"| 受控风险预期规则召回率 | {metrics['expected_dynamic_rule_recall']:.1%} | 30 个风险孪生中，动态审计是否抓到对应行为规则 |",
        f"| 受控风险非放行召回率 | {metrics['controlled_risk_non_allow_recall']:.1%} | 风险孪生是否至少进入 REVIEW/BLOCK |",
        f"| 原始真实 Skill 放行率 | {metrics['original_allow_rate']:.1%} | 正常真实脚本是否未被动态审计误伤 |",
        f"| adversarial 轮触发证明 | {metrics['adversarial_trigger_attestation_rate']:.1%} | 风险事件是否确实只在对抗轮被观察 |",
        f"| 三轮证明完整率 | {metrics['three_round_attestation_rate']:.1%} | 每个包是否完成三类输入证明 |",
        f"| 容器安全门通过率 | {metrics['container_security_gate_rate']:.1%} | 镜像、断网、只读、非 root 等门是否全部成立 |",
        f"| 容器清理通过率 | {metrics['cleanup_verification_rate']:.1%} | 每次运行后是否验证无残留 |",
        f"| 样本树不变率 | {metrics['case_tree_immutability_rate']:.1%} | 扫描前后第三方包哈希是否一致 |",
        f"| 动态决策增量 | {metrics['decision_lift_cases']}/{metrics['cases']} | 动态证据使最终决策比静态更严格的样本数 |",
        f"| 单包动态耗时 | 中位 {metrics['latency_ms']['median']} ms，均值 {metrics['latency_ms']['mean']} ms，最大 {metrics['latency_ms']['max']} ms | 含三轮容器运行与安全门校验 |",
        "",
        "## 分风险类型结果",
        "",
        "| 风险类型 | 样本数 | 对应规则命中 | 非放行 | adversarial 轮事件 |",
        "|---|---:|---:|---:|---:|",
    ]
    for risk_type, values in metrics["per_risk_type"].items():
        lines.append(f"| {risk_type} | {values['support']} | {values['expected_rule_detected']} | {values['non_allow']} | {values['adversarial_round_event']} |")
    lines.extend([
        "",
        "## 6 个真实 Skill 的选择原因与结果",
        "",
        "| 原型 | 发布方 | 运行时 | 选择原因 | 原始动态决策 |",
        "|---|---|---|---|---|",
    ])
    for record in (row for row in records if row["variant"] == "original"):
        lines.append(
            f"| {record['pair_group']} | {record['publisher']} | {record['runtime']} | {record['selection_reason']} | {dynamic_by_id[record['case_id']]['decision']} |"
        )
    lines.extend([
        "",
        "## 逐样本静态/动态对照",
        "",
        "| 样本 | 类型 | 风险 | 静态 | 动态 | 预期动态规则 | 命中 |",
        "|---|---|---|---|---|---|---|",
    ])
    for record in records:
        static = static_by_id[record["case_id"]]
        dynamic = dynamic_by_id[record["case_id"]]
        lines.append(
            f"| {record['case_id']} | {record['variant']} | {record['risk_type']} | {static['decision']} | {dynamic['decision']} | {record.get('expected_rule_id') or '-'} | "
            f"{'是' if dynamic['expected_rule_detected'] is True else ('否' if dynamic['expected_rule_detected'] is False else '-')} |"
        )
    lines.extend([
        "",
        "## 可用于答辩的准确表述",
        "",
        "本实验不是执行网络上已知恶意 Skill，而是从 OpenAI 与 Anthropic 官方仓库选取许可证清晰、人工确认低风险且含真实脚本的 Skill。系统先原样运行真实脚本，再在保留完整包和原始入口的条件下加入受控风险包装器。36 个包均在同一套安装前 Docker 沙箱中完成三轮试运行，记录可解释行为事件、容器安全门和清理证明。",
        "",
        "受控风险孪生只证明系统对这些运行时行为的检测能力，不能据此声称上游官方 Skill 本身恶意。语言级钩子仍可能被刻意绕过；Docker 隔离是安全边界，动态遥测不是内核级完整行为监控。",
        "",
        "## 证据文件",
        "",
        "- `run_manifest.json`：工具、配置、来源与运行环境哈希",
        "- `static_results.jsonl`：36 个包的静态结果",
        "- `dynamic_results.jsonl`：36 个包的动态摘要",
        "- `dynamic_results/*.json`：逐包完整容器、事件、安全门与清理证据",
        "- `metrics.json`：冻结指标的机器可读结果",
        "- `acceptance.json`：按预先阈值计算的验收结论",
    ])
    return "\n".join(lines) + "\n"


def run(output: Path, static_workers: int, static_timeout_seconds: int) -> dict[str, Any]:
    records, source_lock, contract = verify_dataset()
    if output.exists() and any(output.iterdir()):
        raise EvaluationError(f"Output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    scanner = REPRODUCTION_ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
    if not scanner.is_file():
        raise EvaluationError(f"Cisco Skill Scanner unavailable: {scanner}")
    policy = load_policy()
    process_runner = ProcessRunner(
        timeout_seconds=static_timeout_seconds,
        cache_root=DEMO_ROOT / "data" / "cache" / "third_party_dynamic_pairs_v1",
        extra_path=scanner.parent,
    )
    version = process_runner.run([str(scanner), "--version"])
    if version.returncode != 0:
        raise EvaluationError("Could not query Cisco Skill Scanner version")
    adapter = SkillScannerAdapter(scanner=scanner, runner=process_runner)
    dynamic_config = load_multiruntime_config(CONFIG_PATH)
    run_manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "running",
        "started_at": now_iso(),
        "dataset": {"source_lock_sha256": sha256_file(DATA_ROOT / "source_lock.json"), "manifest_sha256": source_lock["manifest_sha256"], "cases": len(records)},
        "contract": {"path": str(CONTRACT_PATH.relative_to(REPRODUCTION_ROOT)), "sha256": sha256_file(CONTRACT_PATH), "status": contract["contract_status"]},
        "static": {"scanner_version": (version.stdout or version.stderr).strip().splitlines()[0], "scanner_sha256": sha256_file(scanner), "policy_sha256": sha256_file(DEFAULT_POLICY_PATH), "workers": static_workers},
        "dynamic": {"backend_id": BACKEND_ID, "config_sha256": dynamic_config.sha256, "timeout_seconds_per_case": contract["execution"]["container_timeout_seconds_per_case"]},
        "environment": {"python": sys.version, "platform": platform.platform(), "known_malicious_third_party_executed": False},
    }
    write_json(output / "run_manifest.json", run_manifest)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=static_workers, thread_name_prefix="dynamic-pairs-static") as executor:
        static_results = list(executor.map(lambda record: static_scan(adapter, policy, record), records))
    write_jsonl(output / "static_results.jsonl", static_results)
    dynamic_results: list[dict[str, Any]] = []
    timeout_seconds = float(contract["execution"]["container_timeout_seconds_per_case"])
    for index, record in enumerate(records, start=1):
        print(json.dumps({"phase": "dynamic", "case": index, "total": len(records), "case_id": record["case_id"]}, ensure_ascii=False), flush=True)
        dynamic_results.append(dynamic_scan(dynamic_config, record, timeout_seconds, output))
    write_jsonl(output / "dynamic_results.jsonl", dynamic_results)
    docker_cli = discover_docker_cli()
    residual_call = run_docker_cli(
        [*_docker_prefix(docker_cli), "container", "ls", "--all", "--filter", f"label=aegis.dynamic.backend={BACKEND_ID}", "--format", "{{.ID}}"],
        timeout_seconds=15,
    )
    residual = [line.strip() for line in residual_call.stdout.splitlines() if line.strip()] if residual_call.return_code == 0 else ["RESIDUAL_CHECK_FAILED"]
    metrics = compute_metrics(records, static_results, dynamic_results)
    accepted = acceptance(metrics, contract)
    accepted["residual_containers"] = residual
    accepted["passed"] = accepted["passed"] and not residual
    write_json(output / "metrics.json", metrics)
    write_json(output / "acceptance.json", accepted)
    run_manifest["status"] = "completed"
    run_manifest["completed_at"] = now_iso()
    run_manifest["wall_seconds"] = round(time.perf_counter() - started, 3)
    run_manifest["outputs"] = {
        name: {"sha256": sha256_file(output / name), "bytes": (output / name).stat().st_size}
        for name in ("static_results.jsonl", "dynamic_results.jsonl", "metrics.json", "acceptance.json")
    }
    write_json(output / "run_manifest.json", run_manifest)
    result = {"run_id": RUN_ID, "acceptance": accepted, "metrics": metrics, "wall_seconds": run_manifest["wall_seconds"]}
    (output / "REPORT.md").write_text(build_report(records, static_results, dynamic_results, metrics, result), encoding="utf-8", newline="\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--static-workers", type=int, default=4)
    parser.add_argument("--static-timeout-seconds", type=int, default=150)
    args = parser.parse_args()
    if not 1 <= args.static_workers <= 8:
        raise EvaluationError("static-workers must be 1..8")
    result = run(args.output.resolve(), args.static_workers, args.static_timeout_seconds)
    print(json.dumps({"run_id": result["run_id"], "passed": result["acceptance"]["passed"], "metrics": result["metrics"]}, ensure_ascii=False))
    return 0 if result["acceptance"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
