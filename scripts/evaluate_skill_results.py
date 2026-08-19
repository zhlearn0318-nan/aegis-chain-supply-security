"""Evaluate Cisco Skill Scanner JSON against the local labelled fixture set."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


RISKY = {"HIGH", "CRITICAL"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    scan = json.loads(args.results.read_text(encoding="utf-8"))
    truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))

    expected = {
        Path(sample["path"]).name: sample["label"] == "malicious"
        for sample in truth["samples"]
    }
    observed = {
        Path(item["skill_path"]).name: item["max_severity"].upper() in RISKY
        for item in scan["results"]
    }

    rows = []
    tp = tn = fp = fn = 0
    for name, is_malicious in expected.items():
        predicted = observed.get(name, False)
        if predicted and is_malicious:
            tp += 1
            outcome = "TP"
        elif predicted and not is_malicious:
            fp += 1
            outcome = "FP"
        elif not predicted and is_malicious:
            fn += 1
            outcome = "FN"
        else:
            tn += 1
            outcome = "TN"
        rows.append(
            {
                "sample": name,
                "expected": "malicious" if is_malicious else "benign",
                "predicted": "malicious" if predicted else "benign",
                "outcome": outcome,
            }
        )

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    report = {
        "threshold": "HIGH_OR_CRITICAL",
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "samples": rows,
    }

    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
