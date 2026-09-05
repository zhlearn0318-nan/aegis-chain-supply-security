from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
DEFAULT_INPUT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_v1"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_source_disjoint_v1"
DATASET_ID = "ProtectSkills/MaliciousSkillBench"
DATASET_REVISION = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
EXPECTED_FILES = {
    "primary.parquet": "1d6382017f259bde0b699d402318f3c03f16b2e8ed2363a346b77a5465f06a06",
    "splits/source_disjoint.parquet": "9fae37c53b6ad47070d118e9bc4cdafd82c416a68b7e74847b4e0dd9d66bd276",
    "schema.json": "2165cc30c6555873b31800869734637fd571148bbf12c40315ce4600ae602378",
    "source_registry.csv": "b0f776d222097c6c33b98fa4d120c44014f2eef1ece5a73a1d1769b95f7ce8a6",
}
EXPECTED_SPLIT_COUNTS = {"train": 7_513, "validation": 835, "test": 1_384, "excluded": 8}
EXPECTED_TEST_LABELS = {"0": 545, "1": 839}
CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")


class IntakeError(RuntimeError):
    """Raised when the benchmark cannot be materialized without ambiguity."""


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def verify_source_files(input_root: Path) -> dict[str, str]:
    actual: dict[str, str] = {}
    for relative, expected in EXPECTED_FILES.items():
        path = input_root / relative
        if not path.is_file() or path.is_symlink():
            raise IntakeError(f"Pinned dataset file is missing or linked: {relative}")
        digest = sha256_file(path)
        if digest != expected:
            raise IntakeError(f"Pinned dataset hash mismatch: {relative}={digest}")
        actual[relative] = digest
    return actual


def safe_case_id(value: Any) -> str:
    case_id = str(value or "")
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise IntakeError(f"Unsafe benchmark_id: {case_id!r}")
    return case_id.lower()


def public_text(row: dict[str, Any]) -> tuple[str, str]:
    exact = row.get("skill_text")
    public = row.get("public_skill_text")
    if isinstance(exact, str) and exact:
        return exact, "skill_text"
    if isinstance(public, str) and public:
        expected = str(row.get("public_text_sha256") or "")
        actual = sha256_bytes(public.encode("utf-8"))
        if not expected or expected != actual:
            raise IntakeError(f"Sanitized public text hash mismatch: {row.get('benchmark_id')}")
        return public, "public_skill_text"
    raise IntakeError(f"No released text is available: {row.get('benchmark_id')}")


def _to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if hasattr(value, "tolist"):
        value = value.tolist()
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value]


def _records_by_id(frame: Any) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for raw in frame.to_dict(orient="records"):
        case_id = str(raw.get("benchmark_id") or "")
        if not case_id or case_id in records:
            raise IntakeError(f"Missing or duplicate primary benchmark_id: {case_id!r}")
        records[case_id] = raw
    return records


def load_test_rows(input_root: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    try:
        import pandas as pd
    except (ImportError, OSError) as exc:
        raise IntakeError(
            "A working pandas+pyarrow environment is required only for benchmark preparation"
        ) from exc

    primary = pd.read_parquet(input_root / "primary.parquet")
    split = pd.read_parquet(input_root / "splits" / "source_disjoint.parquet")
    split_counts = {str(key): int(value) for key, value in split["split"].value_counts().items()}
    if split_counts != EXPECTED_SPLIT_COUNTS:
        raise IntakeError(f"Official split counts drifted: {split_counts}")

    test = split.loc[split["split"] == "test", ["benchmark_id", "label", "source_id"]].copy()
    if test["benchmark_id"].duplicated().any():
        raise IntakeError("Official test split contains duplicate benchmark IDs")
    label_counts = {str(key): int(value) for key, value in test["label"].value_counts().items()}
    if label_counts != EXPECTED_TEST_LABELS:
        raise IntakeError(f"Official test labels drifted: {label_counts}")

    primary_by_id = _records_by_id(primary)
    rows: list[dict[str, Any]] = []
    for split_row in test.sort_values("benchmark_id").to_dict(orient="records"):
        benchmark_id = str(split_row["benchmark_id"])
        row = primary_by_id.get(benchmark_id)
        if row is None:
            raise IntakeError(f"Split ID is absent from primary.parquet: {benchmark_id}")
        if str(row.get("label")) != str(split_row.get("label")):
            raise IntakeError(f"Label disagreement between official files: {benchmark_id}")
        if str(row.get("source_id")) != str(split_row.get("source_id")):
            raise IntakeError(f"Source disagreement between official files: {benchmark_id}")
        rows.append(row)
    return rows, split_counts


def materialize(input_root: Path, output_root: Path) -> dict[str, Any]:
    source_hashes = verify_source_files(input_root)
    rows, split_counts = load_test_rows(input_root)
    output_root.parent.mkdir(parents=True, exist_ok=True)
    if output_root.exists():
        raise IntakeError(f"Output already exists; refusing to replace frozen data: {output_root}")

    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        cases_root = staging / "cases"
        labels_root = staging / "ground_truth"
        cases_root.mkdir()
        labels_root.mkdir()
        scan_manifest: list[dict[str, Any]] = []
        labels: list[dict[str, Any]] = []
        total_bytes = 0
        text_origins: Counter[str] = Counter()
        unavailable_reasons: Counter[str] = Counter()
        for row in rows:
            benchmark_id = str(row["benchmark_id"])
            case_id = safe_case_id(benchmark_id)
            text, text_field = public_text(row)
            data = text.encode("utf-8")
            text_hash = sha256_bytes(data)
            case_root = cases_root / case_id
            case_root.mkdir()
            skill_path = case_root / "SKILL.md"
            scan_ready = True
            unavailability_reason = None
            try:
                skill_path.write_bytes(data)
                if sha256_file(skill_path) != text_hash:
                    raise IntakeError(f"Materialized text verification failed: {benchmark_id}")
            except OSError:
                # Endpoint protection may deliberately make a known-malicious
                # signature unreadable immediately after the write.  Do not
                # disable it or silently scan a changed placeholder.  Remove
                # the blocked artifact and preserve a label-blind failure state
                # that the evaluator maps to fail-closed UNKNOWN.
                try:
                    skill_path.unlink(missing_ok=True)
                except OSError as exc:
                    raise IntakeError(
                        f"Host content filter blocked and retained a sample: {benchmark_id}"
                    ) from exc
                scan_ready = False
                unavailability_reason = "HOST_CONTENT_FILTER_BLOCKED"
                unavailable_reasons[unavailability_reason] += 1
                (case_root / "MATERIALIZATION_BLOCKED.txt").write_text(
                    "The host content filter prevented exact static-text materialization.\n",
                    encoding="utf-8",
                    newline="\n",
                )
            total_bytes += len(data)
            text_origins[text_field] += 1
            scan_manifest.append({
                "case_id": case_id,
                "benchmark_id": benchmark_id,
                "local_path": f"cases/{case_id}",
                "skill_text_sha256": text_hash,
                "skill_text_bytes": len(data),
                "text_field": text_field,
                "scan_ready": scan_ready,
                "unavailability_reason": unavailability_reason,
            })
            labels.append({
                "case_id": case_id,
                "benchmark_id": benchmark_id,
                "label": str(row["label"]),
                "source_id": str(row["source_id"]),
                "source_name": str(row.get("source_name") or ""),
                "source_ids": _to_list(row.get("source_ids")),
                "provenance": str(row.get("provenance") or ""),
                "evidence_type": None if row.get("evidence_type") is None else str(row.get("evidence_type")),
                "structural_family_id": None if row.get("structural_family_id") is None else str(row.get("structural_family_id")),
                "attack_category_codes": _to_list(row.get("attack_category_codes")),
                "impact_category_codes": _to_list(row.get("impact_category_codes")),
                "release_status": str(row.get("release_status") or ""),
                "text_redacted": bool(row.get("text_redacted")),
                "original_text_withheld": bool(row.get("original_text_withheld")),
                "upstream_normalized_hash": str(row.get("normalized_hash") or ""),
                "upstream_exact_hash": str(row.get("exact_hash") or ""),
                "materialized_skill_text_sha256": text_hash,
            })

        write_jsonl(staging / "scan_manifest.jsonl", scan_manifest)
        write_jsonl(labels_root / "labels.jsonl", labels)
        (staging / "case_ids.txt").write_text(
            "".join(f"{row['case_id']}\n" for row in scan_manifest),
            encoding="utf-8",
            newline="\n",
        )
        intake = {
            "schema_version": "1.0",
            "status": "verified_before_first_scan",
            "prepared_at": now_iso(),
            "dataset_id": DATASET_ID,
            "dataset_revision": DATASET_REVISION,
            "protocol": "official_source_disjoint_test_full",
            "license_scope": "CC-BY-4.0 for authored metadata/annotations/splits; upstream terms remain on third-party artifacts",
            "source_file_sha256": source_hashes,
            "official_split_counts": split_counts,
            "cases": len(scan_manifest),
            "label_counts": dict(sorted(Counter(row["label"] for row in labels).items())),
            "source_counts": dict(sorted(Counter(row["source_id"] for row in labels).items())),
            "text_origins": dict(sorted(text_origins.items())),
            "materialized_total_bytes": total_bytes,
            "scan_ready_cases": sum(bool(row["scan_ready"]) for row in scan_manifest),
            "unavailable_cases": len(scan_manifest) - sum(bool(row["scan_ready"]) for row in scan_manifest),
            "unavailability_reasons": dict(sorted(unavailable_reasons.items())),
            "label_firewall": {
                "scan_manifest_contains_labels": False,
                "ground_truth_path": "ground_truth/labels.jsonl",
                "join_after_scan_only": True,
            },
            "safety_boundary": {
                "artifact_kind": "released static Skill text snapshots",
                "executed_during_preparation": False,
                "full_package_code_execution_claimed": False,
            },
        }
        write_json(staging / "intake_manifest.json", intake)
        (staging / "ATTRIBUTION.md").write_text(
            "# MaliciousSkillBench Source-Disjoint 测试集归属说明\n\n"
            f"- 数据集：`{DATASET_ID}`\n"
            f"- 固定提交：`{DATASET_REVISION}`\n"
            "- 官方页面：https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench\n"
            "- 论文：https://arxiv.org/abs/2608.19901\n"
            "- 协议：官方 Source-Disjoint test 全量 1,384 条。\n"
            "- 许可边界：作者生成的元数据、衍生标注、拆分清单和数据库组织采用 CC BY 4.0；"
            "第三方 Skill 文本继续受其上游许可或使用条款约束。\n"
            "- 安全边界：这里只落地公开静态文本用于扫描，未执行任何样本脚本。\n",
            encoding="utf-8",
            newline="\n",
        )

        for record in scan_manifest:
            path = staging / record["local_path"] / "SKILL.md"
            if record["scan_ready"]:
                if sha256_file(path) != record["skill_text_sha256"]:
                    raise IntakeError(f"Final tree verification failed: {record['case_id']}")
            elif path.exists():
                raise IntakeError(f"Blocked text unexpectedly remained: {record['case_id']}")
        os.replace(staging, output_root)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return intake


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Materialize the full official MaliciousSkillBench Source-Disjoint test split."
    )
    parser.add_argument("--input-root", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = materialize(args.input_root.resolve(), args.output_root.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
