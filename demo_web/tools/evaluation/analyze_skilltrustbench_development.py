from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.datasets.prepare_skilltrustbench import tree_sha256  # noqa: E402
from tools.evaluation.run_skilltrustbench import (  # noqa: E402
    EvaluationError,
    load_json,
    load_jsonl,
    sha256_file,
    write_json,
    write_jsonl,
)


SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_CASE_BYTES = 5 * 1024 * 1024

TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".go", ".rs", ".java",
    ".rb", ".php", ".pl", ".lua", ".sql", ".env", ".properties",
}

RISK_LABEL_NAMES = {
    "T01": "skill_instruction_hijacking",
    "T02": "agent_memory_poisoning",
    "T03": "remote_payload_retrieval_and_execution",
    "T04": "embedded_malicious_code",
    "T05": "unauthorized_access_and_privilege_escalation",
    "T06": "system_persistence",
    "T07": "tool_hijacking_and_spoofing",
    "T08": "insecure_dependencies",
    "T09": "insecure_skill_coding_practices",
}


def rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


FEATURE_PATTERNS: dict[str, re.Pattern[str]] = {
    "network_client": rx(
        r"\b(?:requests\.(?:get|post|put|patch|delete)|urllib\.|urlopen\(|httpx\.|aiohttp\.|"
        r"fetch\s*\(|axios\.|curl\b|wget\b|invoke-webrequest\b|invoke-restmethod\b|net/http)"
    ),
    "outbound_write": rx(
        r"\b(?:requests\.(?:post|put|patch)|axios\.(?:post|put|patch)|fetch\s*\([^\n]{0,240}"
        r"method\s*:\s*['\"](?:post|put|patch)|upload|webhook)"
    ),
    "filesystem_access": rx(
        r"\b(?:open\s*\(|pathlib\.Path|read_text\s*\(|write_text\s*\(|read_bytes\s*\(|"
        r"write_bytes\s*\(|fs\.(?:readFile|writeFile|appendFile)|readfile\s*\(|writefile\s*\()"
    ),
    "environment_access": rx(r"\b(?:os\.environ|os\.getenv|process\.env|\$env:|getenv\s*\()"),
    "credential_location": rx(
        r"(?:\.ssh[/\\]|\.aws[/\\]|\.kube[/\\]|\.config[/\\]|credentials?(?:\.json)?|"
        r"id_rsa|known_hosts|wallet\.dat|keychain|login\.keychain|cookies?(?:\.sqlite)?)"
    ),
    "process_execution": rx(
        r"\b(?:subprocess\.|os\.system\s*\(|child_process|execsync\s*\(|spawn\s*\(|"
        r"powershell(?:\.exe)?\b|cmd(?:\.exe)?\s+/c|bash\s+-c|sh\s+-c)"
    ),
    "dynamic_code_execution": rx(
        r"\b(?:eval\s*\(|exec\s*\(|compile\s*\(|new\s+function\s*\(|"
        r"importlib\.import_module|__import__\s*\()"
    ),
    "shell_injection_sink": rx(
        r"(?:shell\s*=\s*true|os\.system\s*\([^\n]*(?:\+|\{|%s)|"
        r"subprocess\.[a-z_]+\s*\([^\n]*(?:\+|\{|shell\s*=\s*true)|child_process\.exec\s*\()"
    ),
    "sql_injection_sink": rx(
        r"(?:\.execute\s*\([^\n]*(?:\+|\{|%s)|\.query\s*\([^\n]*(?:\+|\{|\$\{))"
    ),
    "hardcoded_secret": rx(
        r"(?:\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk_live_[A-Za-z0-9]{16,}\b|"
        r"(?:api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*['\"][^'\"\n]{8,}['\"])"
    ),
    "placeholder_or_test_secret": rx(
        r"\b(?:example|sample|placeholder|dummy|fake|test[_-]?(?:key|token|secret)|your[_-]?(?:key|token)|"
        r"replace[_ -]?me|changeme|not[_ -]?a[_ -]?real)\b"
    ),
    "plaintext_transport": rx(r"http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b)"),
    "unsafe_temp_file": rx(r"\b(?:tempfile\.mktemp\s*\(|mktemp\s+-u\b|/tmp/[A-Za-z0-9_.-]+)"),
    "privilege_escalation": rx(
        r"\b(?:sudo\b|runas\b|setuid\b|setgid\b|chmod\s+(?:777|[46][0-7]{2})\b|"
        r"chown\s+root\b|takeown\b|icacls\b|se_debug_privilege|administrator\b|uid\s*==\s*0)"
    ),
    "persistence_cron": rx(r"\b(?:crontab\b|/etc/cron(?:tab|\.d)?\b|cron\.(?:daily|hourly|weekly))"),
    "persistence_system_service": rx(
        r"\b(?:systemctl\b|systemd\b|/etc/systemd/system|launchctl\b|launchagents?\b|"
        r"new-service\b|sc(?:\.exe)?\s+create\b|create_service\b)"
    ),
    "persistence_startup": rx(
        r"(?:\\currentversion\\run\b|\b(?:hkcu|hklm):?\\[^\n]{0,120}\\run\b|"
        r"startup[/\\]|\.bashrc\b|\.zshrc\b|\.profile\b|authorized_keys\b|schtasks\b|"
        r"register-scheduledtask\b|task scheduler)"
    ),
    "tool_hijack": rx(
        r"(?:\bPATH\s*=\s*[^\n]*\$?PATH|export\s+PATH\s*=|alias\s+[A-Za-z0-9_.-]+\s*=|"
        r"function\s+[A-Za-z0-9_.-]+\s*\(\)|wrapper\s+(?:script|binary)|replace\s+(?:the\s+)?(?:tool|binary))"
    ),
    "dependency_install": rx(
        r"\b(?:pip(?:3)?\s+install\b|npm\s+(?:install|i)\b|yarn\s+add\b|pnpm\s+add\b|"
        r"cargo\s+install\b|gem\s+install\b|go\s+install\b)"
    ),
    "untrusted_dependency_source": rx(
        r"(?:--extra-index-url\b|--index-url\s+http://|git\+https?://|npm\s+install\s+https?://|"
        r"pip\s+install\s+https?://|curl[^\n]{0,160}\|\s*(?:sh|bash))"
    ),
    "encoding_or_obfuscation": rx(
        r"\b(?:base64\.(?:b64decode|urlsafe_b64decode)|frombase64string|atob\s*\(|"
        r"bytes\.fromhex\s*\(|codecs\.decode\s*\([^\n]*rot_13)"
    ),
    "instruction_override": rx(
        r"\b(?:ignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?|"
        r"override\s+(?:the\s+)?(?:system|developer|safety)\s+(?:prompt|instructions?|rules?)|"
        r"bypass\s+(?:the\s+)?(?:policy|safety|guardrails?)|do\s+not\s+(?:reveal|mention|disclose)|"
        r"hidden\s+instructions?|system\s+prompt)"
    ),
    "memory_poisoning": rx(
        r"\b(?:long[- ]term\s+memory|persistent\s+memory|memory\s+(?:store|file|database)|"
        r"remember\s+this\s+(?:rule|instruction)|write\s+[^\n]{0,80}\s+to\s+memory)"
    ),
    "destructive_operation": rx(
        r"\b(?:rm\s+-rf\b|del\s+/[sq]\b|remove-item\b[^\n]{0,80}-recurse|"
        r"shutil\.rmtree\s*\(|format\s+[a-z]:|diskpart\b)"
    ),
}

DOCUMENTATION_PATTERNS: dict[str, re.Pattern[str]] = {
    "declares_network": rx(r"\b(?:api|http|web|internet|network|online|fetch|download|upload|scrap|url|remote)"),
    "declares_filesystem": rx(r"\b(?:file|filesystem|directory|folder|document|workspace|local path|read|write|save)"),
    "declares_process": rx(r"\b(?:shell|command|terminal|build|compile|execute|run script|developer tool|devtool)"),
    "declares_security": rx(r"\b(?:security|scanner|secret|credential|token|audit|vulnerability|malware|forensic)"),
    "declares_privilege": rx(r"\b(?:sudo|administrator|root|privilege|permission|elevated)"),
    "declares_persistence": rx(r"\b(?:startup|service|scheduled task|cron|daemon|persistent)"),
}

HIGH_SIGNAL_STATIC = {
    "hardcoded_secret", "shell_injection_sink", "sql_injection_sink", "plaintext_transport",
    "unsafe_temp_file", "persistence_cron", "persistence_system_service", "persistence_startup",
    "privilege_escalation", "tool_hijack", "untrusted_dependency_source", "destructive_operation",
}


def capped_count(pattern: re.Pattern[str], text: str, cap: int = 99) -> int:
    return min(sum(1 for _ in pattern.finditer(text)), cap)


def read_text_files(case_root: Path) -> tuple[str, str, dict[str, Any]]:
    chunks: list[str] = []
    skill_text = ""
    total_bytes = 0
    read_files = 0
    skipped_large = 0
    skipped_binary = 0
    extensions: Counter[str] = Counter()
    for path in sorted(item for item in case_root.rglob("*") if item.is_file()):
        extension = path.suffix.lower()
        if path.name == "SKILL.md":
            extension = ".md"
        if extension not in TEXT_EXTENSIONS and path.name != "SKILL.md":
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES or total_bytes + size > MAX_CASE_BYTES:
            skipped_large += 1
            continue
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            skipped_binary += 1
            continue
        text = data.decode("utf-8", errors="replace")
        total_bytes += size
        read_files += 1
        extensions[extension or "<none>"] += 1
        chunks.append(text)
        if path.name == "SKILL.md":
            skill_text = text
    return skill_text, "\n".join(chunks), {
        "text_files_read": read_files,
        "text_bytes_read": total_bytes,
        "skipped_large_files": skipped_large,
        "skipped_binary_files": skipped_binary,
        "extension_counts": dict(sorted(extensions.items())),
    }


def feature_counts(text: str) -> dict[str, int]:
    return {
        name: count
        for name, pattern in FEATURE_PATTERNS.items()
        if (count := capped_count(pattern, text)) > 0
    }


def documentation_flags(skill_text: str) -> list[str]:
    return sorted(name for name, pattern in DOCUMENTATION_PATTERNS.items() if pattern.search(skill_text))


def choose_route(row: dict[str, Any], features: set[str], declarations: set[str]) -> tuple[str, list[str]]:
    group = str(row["selection_group"])
    labels = set(str(value) for value in row.get("risk_labels", []))
    reasons: list[str] = []
    if group.startswith("control_"):
        return "regression_control", ["known_correct_baseline_control"]
    if group.startswith("fp_"):
        if group == "fp_network_context" and "declares_network" in declarations:
            return "evidence_correlation", ["network_behavior_is_declared_by_skill"]
        if group == "fp_filesystem_context" and "declares_filesystem" in declarations:
            return "evidence_correlation", ["filesystem_behavior_is_declared_by_skill"]
        if group == "fp_command_context" and "declares_process" in declarations:
            return "evidence_correlation", ["process_behavior_is_declared_by_skill"]
        if group == "fp_secret_pattern" and (
            "placeholder_or_test_secret" in features or "declares_security" in declarations
        ):
            return "rule_calibration", ["secret_like_value_has_placeholder_or_security_context"]
        if group == "fp_social_or_manifest":
            return "policy_separation", ["metadata_quality_signal_should_not_equal_maliciousness"]
        if group == "fp_file_integrity":
            return "rule_calibration", ["file_magic_signal_requires_content_type_and_use_context"]
        return "evidence_correlation", ["benign_behavior_needs_capability_context"]

    if "T06" in labels and features & {
        "persistence_cron", "persistence_system_service", "persistence_startup"
    }:
        reasons.append("persistence_primitive_visible_in_static_text")
        return "new_static_rule", reasons
    if "T05" in labels and "privilege_escalation" in features:
        reasons.append("privilege_boundary_primitive_visible_in_static_text")
        return "new_static_rule", reasons
    if "T09" in labels and features & HIGH_SIGNAL_STATIC:
        reasons.append("insecure_coding_sink_visible_in_static_text")
        return "new_static_rule", reasons
    if "T08" in labels and features & {"dependency_install", "untrusted_dependency_source"}:
        reasons.append("dependency_source_or_install_signal_visible")
        return "new_static_rule", reasons
    if labels & {"T01", "T02"} and features & {"instruction_override", "memory_poisoning"}:
        reasons.append("instruction_or_memory_intent_requires_contextual_semantics")
        return "semantic_review", reasons
    if "instruction_override" in features:
        reasons.append("instruction_override_language_detected")
        return "semantic_review", reasons
    if features & HIGH_SIGNAL_STATIC:
        reasons.append("concrete_high_signal_primitive_visible")
        return "new_static_rule", reasons
    if features & {
        "network_client", "outbound_write", "filesystem_access", "environment_access",
        "credential_location", "process_execution", "dynamic_code_execution", "encoding_or_obfuscation",
    }:
        reasons.append("individual_primitives_need_cross_file_or_intent_correlation")
        return "evidence_correlation", reasons
    if row.get("base_category") == "wild_real_world":
        reasons.append("wild_real_world_miss_has_no_high_signal_regex_feature")
        return "semantic_review", reasons
    reasons.append("no_actionable_static_feature_in_bounded_text_inspection")
    return "dynamic_validation", reasons


def analyze_case(row: dict[str, Any]) -> dict[str, Any]:
    case_id = str(row["case_id"])
    case_root = (CASES_ROOT / case_id).resolve()
    if not case_root.is_dir() or case_root.parent != CASES_ROOT.resolve():
        raise EvaluationError(f"Development case directory is missing or out of scope: {case_id}")
    expected_hash = str(row["case_tree_sha256"])
    before_hash = tree_sha256(case_root)
    if before_hash != expected_hash:
        raise EvaluationError(f"Development case tree hash differs before inspection: {case_id}")
    skill_text, all_text, access = read_text_files(case_root)
    counts = feature_counts(all_text)
    declarations = documentation_flags(skill_text)
    route, reasons = choose_route(row, set(counts), set(declarations))
    after_hash = tree_sha256(case_root)
    if after_hash != expected_hash:
        raise EvaluationError(f"Development case tree hash differs after inspection: {case_id}")
    return {
        "schema_version": "1.0",
        "split_id": SPLIT_ID,
        "case_id": case_id,
        "selection_group": row["selection_group"],
        "ground_truth": row["ground_truth"],
        "risk_labels": row.get("risk_labels", []),
        "source": row.get("source"),
        "base_category": row.get("base_category"),
        "primary_pattern": row.get("primary_pattern"),
        "attack_patterns": row.get("attack_patterns", []),
        "baseline_decision": row.get("baseline_decision"),
        "baseline_matched_rule_ids": row.get("baseline_matched_rule_ids", []),
        "text_access": access,
        "documentation_capabilities": declarations,
        "normalized_feature_counts": counts,
        "recommended_enhancement": route,
        "recommendation_reason_codes": reasons,
        "case_tree_sha256_before": before_hash,
        "case_tree_sha256_after": after_hash,
        "raw_text_retained": False,
        "inspection_status": "completed_read_only",
    }


def count_nested(rows: Iterable[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(sorted(Counter(str(value) for row in rows for value in row.get(key, [])).items()))


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_route: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_group[str(row["selection_group"])].append(row)
        by_route[str(row["recommended_enhancement"])].append(row)
    feature_case_counts = Counter(
        feature for row in rows for feature in row["normalized_feature_counts"]
    )
    feature_occurrences = Counter()
    for row in rows:
        feature_occurrences.update(row["normalized_feature_counts"])
    top_cases_by_route = {
        route: [row["case_id"] for row in sorted(group_rows, key=lambda item: item["case_id"])[:30]]
        for route, group_rows in sorted(by_route.items())
    }
    return {
        "schema_version": "1.0",
        "split_id": SPLIT_ID,
        "parent_run_id": "2026-08-14-skilltrustbench-full-cisco-parallel-v1",
        "question": "Which missed or falsely flagged skills need new deterministic rules, evidence correlation, semantic review, or later dynamic validation?",
        "inspection_scope": {
            "development_cases": len(rows),
            "regression_cases_opened": 0,
            "read_only_text_only": True,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_case_bytes": MAX_CASE_BYTES,
            "raw_text_retained": False,
        },
        "risk_label_taxonomy": RISK_LABEL_NAMES,
        "selection_group_counts": dict(sorted(Counter(row["selection_group"] for row in rows).items())),
        "ground_truth_counts": dict(sorted(Counter(row["ground_truth"] for row in rows).items())),
        "risk_label_counts": count_nested(rows, "risk_labels"),
        "primary_pattern_counts": dict(sorted(Counter(
            str(row["primary_pattern"]) for row in rows if row.get("primary_pattern")
        ).items())),
        "baseline_matched_rule_case_counts": count_nested(rows, "baseline_matched_rule_ids"),
        "recommended_enhancement_counts": dict(sorted(Counter(
            row["recommended_enhancement"] for row in rows
        ).items())),
        "recommended_cases": top_cases_by_route,
        "normalized_feature_case_counts": dict(sorted(feature_case_counts.items())),
        "normalized_feature_occurrences": dict(sorted(feature_occurrences.items())),
        "group_route_matrix": {
            group: dict(sorted(Counter(row["recommended_enhancement"] for row in group_rows).items()))
            for group, group_rows in sorted(by_group.items())
        },
        "safety": {
            "samples_executed": False,
            "sample_modules_imported": False,
            "sample_dependencies_installed": False,
            "sample_files_modified": False,
            "development_hash_mismatches": 0,
            "regression_content_inspected": False,
        },
        "evidence_boundary": [
            "Regex-derived feature codes identify candidate engineering routes; they are not new benchmark predictions.",
            "Semantic-review candidates require a separately evaluated model prompt and must not auto-block on model opinion alone.",
            "Dynamic-validation candidates remain hypotheses until a disposable sandbox and harmless fixtures exist.",
        ],
        "next_route": "Implement isolated rule/correlation candidates on the development set, then evaluate once on the sealed regression set.",
    }


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        output.write(text)
    os.replace(temporary, path)


def run() -> dict[str, Any]:
    split_manifest = load_json(SPLIT_ROOT / "split_manifest.json")
    if split_manifest.get("split_id") != SPLIT_ID:
        raise EvaluationError("Development split identity differs")
    development = load_jsonl(SPLIT_ROOT / "development_cases.jsonl")
    if len(development) != 120:
        raise EvaluationError(f"Expected 120 development cases, got {len(development)}")
    regression_path = SPLIT_ROOT / "regression_cases.jsonl"
    regression_identity_before = sha256_file(regression_path)
    analyzed = [analyze_case(row) for row in development]
    regression_identity_after = sha256_file(regression_path)
    if regression_identity_after != regression_identity_before:
        raise EvaluationError("Regression manifest changed during development inspection")

    analysis_path = SPLIT_ROOT / "development_feature_analysis.jsonl"
    summary_path = SPLIT_ROOT / "gap_summary.json"
    write_jsonl(analysis_path, analyzed)
    summary = aggregate(analyzed)
    write_json(summary_path, summary)
    analysis_manifest = {
        "schema_version": "1.0",
        "split_id": SPLIT_ID,
        "status": "completed",
        "method": "Bounded read-only text feature extraction; no execution, import, installation, or raw text retention.",
        "inputs": {
            "development_cases.jsonl": {
                "sha256": sha256_file(SPLIT_ROOT / "development_cases.jsonl"),
                "bytes": (SPLIT_ROOT / "development_cases.jsonl").stat().st_size,
            },
            "regression_cases.jsonl": {
                "sha256_before": regression_identity_before,
                "sha256_after": regression_identity_after,
                "opened_for_content_analysis": False,
            },
        },
        "outputs": {
            analysis_path.name: {"sha256": sha256_file(analysis_path), "bytes": analysis_path.stat().st_size},
            summary_path.name: {"sha256": sha256_file(summary_path), "bytes": summary_path.stat().st_size},
        },
        "development_hashes_verified_before_and_after": len(analyzed),
        "development_hash_mismatches": 0,
        "raw_text_retained": False,
    }
    manifest_path = SPLIT_ROOT / "analysis_manifest.json"
    write_json(manifest_path, analysis_manifest)
    write_text_atomic(
        SPLIT_ROOT / "ANALYSIS_SHA256.txt",
        f"{sha256_file(manifest_path)}  analysis_manifest.json\n",
    )
    return {
        "status": "completed",
        "split_id": SPLIT_ID,
        "development_cases_analyzed": len(analyzed),
        "regression_cases_opened": 0,
        "recommended_enhancement_counts": summary["recommended_enhancement_counts"],
        "output_root": str(SPLIT_ROOT),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only feature analysis of the frozen development split")
    parser.parse_args()
    try:
        result = run()
    except (EvaluationError, OSError, json.JSONDecodeError, UnicodeError, KeyError, ValueError) as exc:
        print(f"development analysis failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
