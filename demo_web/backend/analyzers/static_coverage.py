from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-static-coverage-v1"
MAX_FILES = 500
MAX_SECURITY_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_SECURITY_BYTES = 5 * 1024 * 1024

SECURITY_TEXT_EXTENSIONS = {
    ".md", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".xml",
    ".go", ".rs", ".java", ".rb", ".php", ".pl", ".lua", ".sql",
    ".env", ".properties", ".lock",
}
NESTED_ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".whl", ".jar"}
NATIVE_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".wasm", ".bin", ".pyc", ".class"}
UNSUPPORTED_CODE_EXTENSIONS = {".ipynb", ".r", ".scala", ".kt", ".kts", ".swift"}


@dataclass(frozen=True)
class CoverageGap:
    rule_id: str
    severity: str
    relative_path: str
    reason_code: str


def _inside(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def _gap_finding(gap: CoverageGap) -> dict:
    identity = "|".join([gap.rule_id, gap.relative_path, gap.reason_code])
    finding_id = f"{gap.rule_id}_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:12]}"
    titles = {
        "AEGIS_STATIC_CODE_FILE_SKIPPED_TOO_LARGE": "A security-relevant file exceeds the static inspection limit",
        "AEGIS_STATIC_NESTED_ARCHIVE_UNINSPECTED": "A nested archive is not recursively inspected",
        "AEGIS_STATIC_NATIVE_EXECUTABLE_UNINSPECTED": "A native executable is outside source-level inspection",
        "AEGIS_STATIC_UNSUPPORTED_CODE_UNINSPECTED": "A code format is outside the supported static analyzers",
        "AEGIS_STATIC_PYTHON_PARSE_FAILED": "Python source could not be parsed for AST analysis",
        "AEGIS_STATIC_TEXT_DECODE_LOSS": "Security-relevant text could not be decoded losslessly",
        "AEGIS_STATIC_SYMLINK_UNINSPECTED": "A symbolic link prevents complete in-root inspection",
    }
    return finding_dict(
        id=finding_id,
        title=titles[gap.rule_id],
        category="static_coverage_gap",
        severity=gap.severity,
        analyzer=ANALYZER_ID,
        location={"file": gap.relative_path},
        evidence=f"coverage_gap={gap.reason_code}; file={gap.relative_path}; raw_value_retained=false",
        description="Part of the Skill cannot be fully inspected by the current bounded source-level analyzers.",
        remediation="Provide inspectable source, remove nested/binary payloads, split oversized code, or route the artifact to an approved specialist scanner before admission.",
        rule_id=gap.rule_id,
    )


def _summary_finding(counts: dict[str, int]) -> dict:
    ordered = [
        "files_total", "security_text_inspected", "non_code_data_counted",
        "coverage_gap_files", "python_parsed", "python_parse_failed",
    ]
    codes = ",".join(f"{key}:{counts[key]}" for key in ordered)
    identity = hashlib.sha256(codes.encode("utf-8")).hexdigest()[:12]
    return finding_dict(
        id=f"AEGIS_STATIC_COVERAGE_SUMMARY_{identity}",
        title="Static inspection coverage summary",
        category="static_coverage_summary",
        severity="INFO",
        analyzer=ANALYZER_ID,
        location={"file": "SKILL.md"},
        evidence=f"coverage_counts={codes}; raw_value_retained=false",
        description="A deterministic inventory records the source/config scope inspected and any non-code data counted.",
        remediation="Review any accompanying coverage-gap findings before admission.",
        rule_id="AEGIS_STATIC_COVERAGE_SUMMARY",
    )


def analyze_static_coverage(skill_root: Path) -> tuple[list[dict], list[str]]:
    """Inventory static coverage and surface security-relevant uninspected content."""
    root = skill_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Skill root must be a directory")
    if not (root / "SKILL.md").is_file():
        raise ValueError("Skill root is missing SKILL.md")
    counts = {
        "files_total": 0,
        "security_text_inspected": 0,
        "non_code_data_counted": 0,
        "coverage_gap_files": 0,
        "python_parsed": 0,
        "python_parse_failed": 0,
    }
    gaps: list[CoverageGap] = []
    total_security_bytes = 0
    for path in sorted(skill_root.rglob("*"), key=lambda item: item.as_posix().lower()):
        if path.is_symlink():
            counts["files_total"] += 1
            relative = path.relative_to(skill_root).as_posix()
            gaps.append(CoverageGap(
                "AEGIS_STATIC_SYMLINK_UNINSPECTED", "MEDIUM", relative, "symbolic_link"
            ))
            continue
        if not path.is_file():
            continue
        counts["files_total"] += 1
        if counts["files_total"] > MAX_FILES:
            raise ValueError(f"Skill contains more than {MAX_FILES} files")
        resolved = path.resolve(strict=True)
        if not _inside(root, resolved):
            raise ValueError("Skill contains a file outside its root")
        relative = resolved.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        size = path.stat().st_size
        if suffix in NESTED_ARCHIVE_EXTENSIONS:
            gaps.append(CoverageGap(
                "AEGIS_STATIC_NESTED_ARCHIVE_UNINSPECTED", "MEDIUM", relative, "nested_archive"
            ))
            continue
        if suffix in NATIVE_EXECUTABLE_EXTENSIONS:
            gaps.append(CoverageGap(
                "AEGIS_STATIC_NATIVE_EXECUTABLE_UNINSPECTED", "MEDIUM", relative, "native_executable"
            ))
            continue
        if suffix in UNSUPPORTED_CODE_EXTENSIONS:
            gaps.append(CoverageGap(
                "AEGIS_STATIC_UNSUPPORTED_CODE_UNINSPECTED", "MEDIUM", relative, "unsupported_code_format"
            ))
            continue
        if path.name != "SKILL.md" and suffix not in SECURITY_TEXT_EXTENSIONS:
            counts["non_code_data_counted"] += 1
            continue
        if size > MAX_SECURITY_FILE_BYTES:
            gaps.append(CoverageGap(
                "AEGIS_STATIC_CODE_FILE_SKIPPED_TOO_LARGE", "MEDIUM", relative, "security_file_too_large"
            ))
            continue
        if total_security_bytes + size > MAX_TOTAL_SECURITY_BYTES:
            raise ValueError("Skill security-relevant text exceeds the total static inspection budget")
        data = path.read_bytes()
        total_security_bytes += size
        if b"\x00" in data[:8192]:
            gaps.append(CoverageGap(
                "AEGIS_STATIC_TEXT_DECODE_LOSS", "MEDIUM", relative, "binary_content_in_text_extension"
            ))
            continue
        text = data.decode("utf-8", errors="replace")
        if "\ufffd" in text:
            gaps.append(CoverageGap(
                "AEGIS_STATIC_TEXT_DECODE_LOSS", "MEDIUM", relative, "utf8_decode_replacement"
            ))
            continue
        counts["security_text_inspected"] += 1
        if suffix == ".py":
            try:
                ast.parse(text, filename=relative)
                counts["python_parsed"] += 1
            except (SyntaxError, ValueError):
                counts["python_parse_failed"] += 1
                gaps.append(CoverageGap(
                    "AEGIS_STATIC_PYTHON_PARSE_FAILED", "MEDIUM", relative, "python_ast_parse_failed"
                ))
    counts["coverage_gap_files"] = len({gap.relative_path for gap in gaps})
    normalized = [_gap_finding(gap) for gap in gaps]
    by_id = {finding["id"]: finding for finding in normalized}
    findings = sorted(
        by_id.values(),
        key=lambda item: (item["location"].get("file") or "", item["rule_id"] or ""),
    )
    findings.append(_summary_finding(counts))
    return findings, [ANALYZER_ID]
