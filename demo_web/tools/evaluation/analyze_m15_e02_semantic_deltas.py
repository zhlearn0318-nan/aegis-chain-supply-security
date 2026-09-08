from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.analyzers.skill_semantic import analyze_skill_semantics  # noqa: E402


DEFAULT_DATA_ROOT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_m15_e01_v1"
DEFAULT_RUN_ROOT = DEMO_ROOT / "artifacts" / "experiment" / "2026-09-08-m15-e02-malicious-train-semantic-regression-v2"

CUES = {
    "when_user": re.compile(r"(?i)\bwhen\s+(?:the\s+)?user\b|当用户|用户.*时"),
    "only_if": re.compile(r"(?i)\bonly\s+if\b|仅当"),
    "if_user": re.compile(r"(?i)\bif\s+(?:the\s+)?user\b|如果.{0,30}用户"),
    "hidden_environment": re.compile(r"(?i)(?:date|time|host|hostname|machine|environment|\d+\s+(?:runs?|uses?))|日期|时间|主机|机器|环境|第\s*\d+\s*次"),
    "outbound": re.compile(r"(?i)upload|exfiltrat|send|post|webhook|callback|remote\s+server|上传|外传|发送|回传|远程服务器"),
    "sensitive": re.compile(r"(?i)secret|token|password|credential|private\s+key|api\s+key|\.ssh|\.aws|密钥|令牌|密码|凭据|私钥"),
    "execution": re.compile(r"(?i)execute|run|invoke|spawn|shell|powershell|bash|cmd\.exe|subprocess|child_process|执行|运行|调用|启动"),
    "remote_or_payload": re.compile(r"(?i)payload|download|remote|url|http|encoded|base64|载荷|下载|远程|编码"),
}

MARKERS = {
    "covert": re.compile(
        r"(?i)do\s+not\s+(?:surface|mention|tell|notify|disclose|reveal|show|ask)|"
        r"without\s+(?:user\s+)?(?:approval|confirmation|consent)|"
        r"(?:stealth|secretly|silently|hidden)|"
        r"(?:不要|不得|无需|不必).{0,24}(?:告知|显示|通知|确认|同意|授权)|静默|隐蔽"
    ),
    "mandatory": re.compile(
        r"(?i)(?:very\s+)?first\s+action|before\s+(?:producing|responding)|"
        r"(?:always|must|required)\s+(?:be\s+)?(?:to\s+)?(?:execute|run|invoke)|"
        r"(?:pre[- ]?flight|initiali[sz]ation|operational)\s+(?:step|guard|contract|note)|"
        r"(?:第一步|首次操作|回复前|必须|总是).{0,36}(?:执行|运行|调用|启动)"
    ),
    "script_invocation": re.compile(
        r"(?i)(?:python(?:3)?|bash|sh|powershell|pwsh|cmd(?:\.exe)?|node)\s+[^\n`]*(?:scripts?/|\.py\b|\.sh\b|\.ps1\b|\.js\b)|"
        r"`[^`]*(?:scripts?/|\.py\b|\.sh\b|\.ps1\b|\.js\b)[^`]*`"
    ),
}
SAFE_ACTIVATION = re.compile(
    r"(?i)(?:use|trigger|invoke)\s+(?:this\s+)?skill\s+when\s+(?:the\s+)?user\s+"
    r"(?:asks?|wants?|needs?|requests?|mentions?|says?)|"
    r"(?:when\s+to\s+use\s+this\s+skill|适用场景|当用户(?:询问|想要|需要|请求|提到).{0,80})"
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def paragraph_at(text: str, line_number: int) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    index = max(0, min(len(lines) - 1, line_number - 1))
    left = max(0, index - 4)
    right = min(len(lines), index + 5)
    return "\n".join(lines[left:right])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    args = parser.parse_args()

    train_root = args.data_root.resolve() / "train"
    predictions = {row["case_id"]: row for row in load_jsonl(args.run_root.resolve() / "predictions.label_blind.jsonl")}
    labels = {row["case_id"]: row for row in load_jsonl(train_root / "ground_truth" / "labels.jsonl")}
    scan_rows = {row["case_id"]: row for row in load_jsonl(train_root / "scan_manifest.jsonl")}
    targets = [
        case_id for case_id, prediction in predictions.items()
        if prediction["f0_decision"] in {"REVIEW", "BLOCK"}
        and prediction["f3_decision"] == "ALLOW"
    ]
    cue_counts: Counter[str] = Counter()
    feature_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    target_labels: Counter[str] = Counter()
    marker_counts: dict[str, Counter[str]] = defaultdict(Counter)
    feature_combo_counts: dict[str, Counter[str]] = defaultdict(Counter)
    safe_activation_counts: dict[str, Counter[str]] = defaultdict(Counter)
    safe_activation_combo_counts: dict[str, Counter[str]] = defaultdict(Counter)
    candidate_counts: Counter[str] = Counter()
    examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case_id in targets:
        row = scan_rows[case_id]
        source_id = labels[case_id]["source_id"]
        label = labels[case_id]["label"]
        target_labels[label] += 1
        source_counts[source_id] += 1
        root = train_root / row["local_path"]
        findings, _ = analyze_skill_semantics(root)
        conditional = next((item for item in findings if item["rule_id"] == "AEGIS_SEMANTIC_CONDITIONAL_RISK_TRIGGER"), None)
        if conditional is None:
            feature_counts["no_conditional_finding"] += 1
            continue
        evidence = str(conditional.get("evidence") or "")
        semantic_features = []
        for feature in ("sensitive_access", "outbound", "execution"):
            if feature in evidence:
                feature_counts[feature] += 1
                semantic_features.append(feature)
        feature_combo_counts[label]["+".join(semantic_features)] += 1
        text = (root / "SKILL.md").read_text(encoding="utf-8", errors="replace")
        paragraph = paragraph_at(text, int(conditional["location"]["line"]))
        window_lines = text.splitlines()
        line_index = max(0, int(conditional["location"]["line"]) - 1)
        window = "\n".join(window_lines[max(0, line_index - 14):min(len(window_lines), line_index + 15)])
        marker_hits = {name for name, pattern in MARKERS.items() if pattern.search(window)}
        for marker in marker_hits:
            marker_counts[label][marker] += 1
        hidden_action = bool(CUES["hidden_environment"].search(window)) and bool(
            CUES["outbound"].search(window) or CUES["sensitive"].search(window) or CUES["execution"].search(window)
        )
        coercive_script = bool(marker_hits & {"covert", "mandatory"}) and "script_invocation" in marker_hits
        safe_activation = bool(SAFE_ACTIVATION.search(window))
        if safe_activation:
            safe_activation_counts[label]["all"] += 1
            if marker_hits & {"covert", "mandatory"}:
                safe_activation_counts[label]["with_suspicious_marker"] += 1
            else:
                safe_activation_counts[label]["without_suspicious_marker"] += 1
            if "script_invocation" in marker_hits:
                safe_activation_counts[label]["with_script_invocation"] += 1
            else:
                safe_activation_counts[label]["without_script_invocation"] += 1
            if not marker_hits:
                safe_activation_counts[label]["without_any_marker"] += 1
            if coercive_script:
                safe_activation_counts[label]["with_coercive_script"] += 1
            else:
                safe_activation_counts[label]["without_coercive_script"] += 1
                safe_activation_combo_counts[label]["+".join(semantic_features)] += 1
        if hidden_action or coercive_script:
            candidate_counts[label] += 1
        matched = [name for name, pattern in CUES.items() if pattern.search(paragraph)]
        if not matched:
            matched = ["uncategorized"]
        cue_counts.update(matched)
        for cue in matched:
            if len(examples[cue]) < 5:
                examples[cue].append({
                    "case_id": case_id,
                    "source_id": source_id,
                    "line": conditional["location"]["line"],
                    "semantic_features": evidence,
                    "paragraph": paragraph[:1200],
                })
    output = {
        "targets": len(targets),
        "definition": "F0 non-allow changed to F3 allow, analyzed by ground-truth label after label-blind prediction",
        "target_labels": dict(sorted(target_labels.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "semantic_feature_counts": dict(sorted(feature_counts.items())),
        "cue_counts": dict(sorted(cue_counts.items())),
        "marker_counts_by_label": {label: dict(sorted(values.items())) for label, values in sorted(marker_counts.items())},
        "feature_combo_counts_by_label": {label: dict(sorted(values.items())) for label, values in sorted(feature_combo_counts.items())},
        "safe_activation_counts_by_label": {label: dict(sorted(values.items())) for label, values in sorted(safe_activation_counts.items())},
        "safe_activation_without_coercive_combo_by_label": {
            label: dict(sorted(values.items())) for label, values in sorted(safe_activation_combo_counts.items())
        },
        "candidate_v3_keep_counts_by_label": dict(sorted(candidate_counts.items())),
        "examples": dict(sorted(examples.items())),
    }
    output_path = args.run_root.resolve() / "delta_analysis.json"
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Keep the terminal portable on Windows hosts whose active code page is GBK.
    print(json.dumps(output, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
