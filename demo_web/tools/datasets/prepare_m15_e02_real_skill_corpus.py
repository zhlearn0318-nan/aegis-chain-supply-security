from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
DEFAULT_CONFIG = DEMO_ROOT / "config" / "m15_e02_real_skill_corpus_v1.json"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "datasets" / "third_party_skill_e02_v1"
PILOT_ROOT = REPOSITORY_ROOT / "datasets" / "third_party_skill_pilot40_v1"
DYNAMIC_ROOT = REPOSITORY_ROOT / "datasets" / "third_party_skill_dynamic_pairs_v1"
MAX_FILES_PER_CASE = 5_000
MAX_BYTES_PER_CASE = 100 * 1024 * 1024


class IntakeError(RuntimeError):
    pass


ECOSYSTEM_PROFILES: dict[str, tuple[str, str, str]] = {
    "masb-007-meeting-insights-analyzer": ("会议记录洞察与长文本分析", "读取用户提供的会议文本；无脚本入口", "纯自然语言业务分析硬负例"),
    "masb-011-regression-test-generator": ("回归测试设计与模板生成", "读取项目说明和参考文件；生成测试建议", "跨文件开发工具硬负例"),
    "masb-013-mcp-builder": ("MCP 服务设计、实现与评测", "Python 脚本、依赖、网络/API 与文件读写", "多文件多能力合法开发样本"),
    "masb-014-remote-work": ("Azure 远程资源运维指导", "远程 VM、网络和云资源操作说明", "区分合法远程运维与远程执行攻击"),
    "masb-015-xl-cli": ("命令行表格编辑与导出", "CLI 调用、办公文件读写与结果导出", "政企办公自动化高能力样本"),
    "masb-026-process-flow-generator": ("流程图和视觉内容生成", "内容生成；无脚本入口", "低权限单文件真实对照"),
    "masb-027-flow-verifier": ("计划与流程校验", "读取计划文件并给出维护建议", "区分只读校验和修改动作"),
    "masb-033-proposal-formatter": ("交易提案格式化", "处理用户提供的业务文本；无脚本入口", "命令式金融文本正常对照"),
    "masb-037-developing-with-laravel": ("PHP/Laravel 应用开发指导", "项目文件、构建命令和多文件参考资料", "复杂目录开发工具兼容性"),
    "masb-045-dev-swarm-python": ("Python 多代理开发环境初始化", "依赖安装、包源、远程下载和命令执行", "供应链安装链合法高权限样本"),
    "masb-046-privacy-policy-generate": ("隐私政策生成与发布", "内容生成、GitHub Pages 发布说明", "合规内容与部署语义混合样本"),
    "masb-048-api-design": ("API 设计与规范编写", "读取项目上下文和多文件说明", "清单兼容性与开发文本对照"),
    "masb-049-streamlit-development": ("Snowflake/Streamlit 数据应用开发", "企业数据源、外部云服务和应用文件", "政企数据应用接入样本"),
    "masb-051-advertisement": ("广告内容与对象行为生成", "内容生成和参考资源读取", "非典型目录与描述结构兼容性"),
    "masb-054-pattern-recognition-specialist": ("代码模式识别与分析", "读取代码；超长元数据；无直接执行入口", "元数据边界和分析型文本对照"),
    "masb-055-retrospective-base": ("团队复盘与教练式引导", "处理用户提供的文本；无脚本入口", "长自然语言指令误报对照"),
    "masb-060-general-frontend-security": ("前端安全审查指导", "分析代码与安全概念；无脚本入口", "含 OWASP/XSS/CSRF 等危险词的防御性硬负例"),
    "masb-061-godot-mcp-auto-launcher": ("Godot MCP 自动启动", "子进程、网络、文件访问和自动启动", "真实自动启动器高权限样本"),
    "masb-063-claude-code-hooks": ("Claude Code Hook 自动化", "钩子、工作流命令和外部工具", "验证自动化控制链与不可达示例"),
    "masb-065-secure-code-guardian": ("安全编码与认证授权审查", "分析代码、密钥和认证术语；无直接执行入口", "防御性安全文本硬负例"),
    "masb-079-ohmydebn-skill": ("Debian 系统配置与管理", "系统命令、配置文件和持久化相关操作", "真实运维文本高权限样本"),
    "masb-083-pg-style-editor": ("长文风格编辑", "处理用户提供的文本；无脚本入口", "低权限内容编辑正常对照"),
    "masb-087-tauri-app": ("Tauri 桌面应用脚手架", "Rust/前端构建命令、依赖与项目写入", "多语言脚手架和构建链样本"),
    "masb-094-similarity-led": ("电子元件相似度分析", "读取工程数据并计算相似度；无明显执行能力", "跨领域专业技术文本正常对照"),
}


OFFICIAL_STRATA = {
    "openai-jupyter-notebook--original": "developer_tool",
    "openai-plugin-creator--original": "developer_tool",
    "openai-security-ownership-map--original": "enterprise_governance",
    "openai-chatgpt-apps--original": "developer_tool",
    "openai-openai-docs--original": "workflow_guidance",
    "anthropic-algorithmic-art--original": "content_design",
}


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise IntakeError(f"Expected a JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise IntakeError(f"Expected an object at {path}:{line_number}")
        records.append(value)
    return records


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_reparse(path: Path) -> bool:
    return bool(getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400)


def inspect_source_tree(root: Path) -> tuple[int, int]:
    if not root.is_dir() or root.is_symlink() or is_reparse(root):
        raise IntakeError(f"Unsafe or missing source directory: {root}")
    count = 0
    total = 0
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_root = Path(current)
        for name in directory_names:
            path = current_root / name
            if path.is_symlink() or is_reparse(path):
                raise IntakeError(f"Links/reparse points are prohibited: {path}")
        for name in file_names:
            path = current_root / name
            if path.is_symlink() or is_reparse(path) or not path.is_file():
                raise IntakeError(f"Unsafe file in source tree: {path}")
            count += 1
            total += path.stat().st_size
            if count > MAX_FILES_PER_CASE or total > MAX_BYTES_PER_CASE:
                raise IntakeError(f"Source case exceeds intake limits: {root}")
    if count == 0:
        raise IntakeError(f"Source case is empty: {root}")
    return count, total


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative.startswith("ground_truth/") or relative == "intake_manifest.json":
            continue
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(sha256_file(path).encode("ascii") + b"\n")
    return digest.hexdigest()


def source_tree_sha256(root: Path) -> str:
    """Match the byte-level tree hash used by the frozen pilot dataset."""
    digest = hashlib.sha256()
    # Keep Path's platform-native ordering because the already frozen source
    # manifests were produced that way on Windows.
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def dynamic_source_tree_sha256(root: Path) -> str:
    """Match the path-plus-file-digest hash used by the frozen dynamic dataset."""
    digest = hashlib.sha256()
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    ):
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def git_value(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True, encoding="utf-8"
    )
    return completed.stdout.strip()


def verify_pinned_repositories(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    locked: dict[str, dict[str, Any]] = {}
    for key, record in config["pinned_repositories"].items():
        root = REPOSITORY_ROOT / record["local_root"]
        actual_commit = git_value(root, "rev-parse", "HEAD")
        if actual_commit != record["commit"]:
            raise IntakeError(f"Pinned repository commit drifted for {key}: {actual_commit}")
        if git_value(root, "status", "--porcelain"):
            raise IntakeError(f"Pinned repository is dirty: {root}")
        locked[key] = {**record, "verified_commit": actual_commit, "working_tree_clean": True}
    return locked


def classify_case(config: dict[str, Any], section: str, case_id: str) -> str:
    groups = config[section]
    matches = [name for name, case_ids in groups.items() if case_id in case_ids]
    if len(matches) != 1:
        raise IntakeError(f"Case must have exactly one workload class: {case_id} -> {matches}")
    return matches[0]


def copy_case(source: Path, destination: Path) -> tuple[int, int, str]:
    expected_files, expected_bytes = inspect_source_tree(source)
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    actual_files, actual_bytes = inspect_source_tree(destination)
    if (actual_files, actual_bytes) != (expected_files, expected_bytes):
        raise IntakeError(f"Copy drifted for {source}")
    return actual_files, actual_bytes, tree_sha256(destination)


def materialize(config_path: Path, output_root: Path) -> dict[str, Any]:
    if output_root.exists():
        raise IntakeError(f"Output already exists; refusing to replace frozen data: {output_root}")
    config = read_json(config_path)
    locked_repositories = verify_pinned_repositories(config)
    cases_root = output_root / "cases"
    ground_truth_root = output_root / "ground_truth"
    cases_root.mkdir(parents=True)
    ground_truth_root.mkdir()

    scan_records: list[dict[str, Any]] = []
    label_records: list[dict[str, Any]] = []

    pilot_rows = [
        row for row in read_jsonl(PILOT_ROOT / "pilot_manifest.jsonl")
        if row.get("source_kind") == "real_ecosystem_weak_negative"
    ]
    if len(pilot_rows) != 24:
        raise IntakeError(f"Expected 24 ecosystem weak negatives, found {len(pilot_rows)}")
    for row in sorted(pilot_rows, key=lambda item: item["case_id"]):
        case_id = str(row["case_id"])
        source = PILOT_ROOT / str(row["local_path"])
        destination = cases_root / case_id
        file_count, total_bytes, case_hash = copy_case(source, destination)
        if source_tree_sha256(destination) != row.get("case_tree_sha256"):
            raise IntakeError(f"Pilot source tree hash drifted: {case_id}")
        workload_class = classify_case(config, "ecosystem_case_classes", case_id)
        function_summary, permission_surface, test_value = ECOSYSTEM_PROFILES[case_id]
        scan_records.append({
            "case_id": case_id,
            "local_path": f"cases/{case_id}",
            "source_kind": "ecosystem_weak_negative",
            "publisher": str(row["repository"]).split("/", 1)[0],
            "repository": row["repository"],
            "repository_commit": row["repository_commit"],
            "skill_path": row["skill_path"],
            "license_spdx": row["license_spdx"],
            "license_sha256": row["license_sha256"],
            "case_tree_sha256": case_hash,
            "file_count": file_count,
            "total_bytes": total_bytes,
        })
        label_records.append({
            "case_id": case_id,
            "expected_legitimacy": "weak_legitimate",
            "workload_class": workload_class,
            "stratum": "content_or_workflow" if workload_class == "low_permission" else "developer_or_ops",
            "function_summary": function_summary,
            "permission_surface": permission_surface,
            "selection_reason": f"固定种子选中的许可证明确真实生态 Skill；{test_value}。",
        })

    original_rows = [
        row for row in read_jsonl(DYNAMIC_ROOT / "manifest.jsonl") if row.get("variant") == "original"
    ]
    if len(original_rows) != 6:
        raise IntakeError(f"Expected 6 official original script Skills, found {len(original_rows)}")
    for row in sorted(original_rows, key=lambda item: item["case_id"]):
        case_id = str(row["case_id"])
        source = DYNAMIC_ROOT / str(row["local_path"])
        destination = cases_root / case_id
        file_count, total_bytes, case_hash = copy_case(source, destination)
        if dynamic_source_tree_sha256(destination) != row.get("case_tree_sha256"):
            raise IntakeError(f"Official original tree hash drifted: {case_id}")
        workload_class = classify_case(config, "official_original_classes", case_id)
        scan_records.append({
            "case_id": case_id,
            "local_path": f"cases/{case_id}",
            "source_kind": "official_script_original",
            "publisher": row["publisher"],
            "repository": "openai/skills" if row["publisher"] == "OpenAI" else "anthropics/skills",
            "repository_commit": row["source_commit"],
            "skill_path": row["source_skill_path"],
            "license_spdx": row["license"],
            "license_sha256": row["license_sha256"],
            "case_tree_sha256": case_hash,
            "file_count": file_count,
            "total_bytes": total_bytes,
        })
        label_records.append({
            "case_id": case_id,
            "expected_legitimacy": "manually_screened_legitimate",
            "workload_class": workload_class,
            "stratum": OFFICIAL_STRATA[case_id],
            "function_summary": case_id.removesuffix("--original").replace("-", " "),
            "permission_surface": row["manual_screening"],
            "selection_reason": row["selection_reason"],
        })

    for selection in config["additional_skills"]:
        case_id = selection["case_id"]
        repository_key = selection["repository"]
        repository = locked_repositories[repository_key]
        repository_root = REPOSITORY_ROOT / repository["local_root"]
        source = repository_root / selection["skill_path"]
        license_path = source / selection["license_path"]
        if not license_path.is_file():
            raise IntakeError(f"Declared license is missing: {license_path}")
        destination = cases_root / case_id
        file_count, total_bytes, case_hash = copy_case(source, destination)
        scan_records.append({
            "case_id": case_id,
            "local_path": f"cases/{case_id}",
            "source_kind": "additional_pinned_public_skill",
            "publisher": selection["publisher"],
            "repository": "openai/skills" if repository_key == "openai" else "anthropics/skills",
            "repository_commit": repository["commit"],
            "skill_path": selection["skill_path"],
            "license_spdx": selection["license_spdx"],
            "license_sha256": sha256_file(license_path),
            "case_tree_sha256": case_hash,
            "file_count": file_count,
            "total_bytes": total_bytes,
        })
        label_records.append({
            "case_id": case_id,
            "expected_legitimacy": "public_official_legitimate",
            "workload_class": selection["workload_class"],
            "stratum": selection["stratum"],
            "function_summary": case_id.split("-", 1)[1].replace("-", " "),
            "permission_surface": "以完整 Skill 文件树和公开功能说明为准；高权限样本仍须接受数据流审查。",
            "selection_reason": selection["selection_reason"],
        })

    if len(scan_records) != 40 or len({row["case_id"] for row in scan_records}) != 40:
        raise IntakeError("The frozen corpus must contain exactly 40 unique cases")
    if {row["case_id"] for row in scan_records} != {row["case_id"] for row in label_records}:
        raise IntakeError("Scan and ground-truth case IDs disagree")
    scan_records.sort(key=lambda row: row["case_id"])
    label_records.sort(key=lambda row: row["case_id"])
    write_jsonl(output_root / "scan_manifest.jsonl", scan_records)
    write_jsonl(ground_truth_root / "labels.jsonl", label_records)
    write_json(output_root / "source_lock.json", {
        "schema_version": "1.0",
        "dataset_id": config["dataset_id"],
        "config_sha256": sha256_file(config_path),
        "pinned_repositories": locked_repositories,
        "derived_sources": {
            "pilot_source_lock_sha256": sha256_file(DEMO_ROOT / "baseline" / "third_party_skill_pilot40_v1" / "source_lock.json"),
            "dynamic_source_lock_sha256": sha256_file(DYNAMIC_ROOT / "source_lock.json"),
        },
    })
    workload_counts = Counter(row["workload_class"] for row in label_records)
    source_counts = Counter(row["source_kind"] for row in scan_records)
    intake = {
        "schema_version": "1.0",
        "dataset_id": config["dataset_id"],
        "case_count": len(scan_records),
        "source_kind_counts": dict(sorted(source_counts.items())),
        "workload_class_counts": dict(sorted(workload_counts.items())),
        "labels_absent_from_scan_manifest": all(
            not ({"expected_legitimacy", "workload_class", "stratum"} & set(row)) for row in scan_records
        ),
        "scripts_executed": False,
        "links_allowed": False,
        "scan_input_tree_sha256": tree_sha256(output_root),
    }
    write_json(output_root / "intake_manifest.json", intake)
    return intake


def verify_scan_inputs(output_root: Path) -> dict[str, Any]:
    intake = read_json(output_root / "intake_manifest.json")
    rows = read_jsonl(output_root / "scan_manifest.jsonl")
    if len(rows) != 40 or len({row.get("case_id") for row in rows}) != 40:
        raise IntakeError("Frozen scan manifest must contain 40 unique cases")
    forbidden = {"expected_legitimacy", "workload_class", "stratum", "selection_reason"}
    for row in rows:
        if forbidden & set(row):
            raise IntakeError(f"Ground-truth field leaked into scan manifest: {row.get('case_id')}")
        case_root = output_root / str(row["local_path"])
        inspect_source_tree(case_root)
        if tree_sha256(case_root) != row["case_tree_sha256"]:
            raise IntakeError(f"Case tree hash drifted: {row['case_id']}")
    actual_hash = tree_sha256(output_root)
    if actual_hash != intake.get("scan_input_tree_sha256"):
        raise IntakeError("Frozen scan-input tree hash drifted")
    return {
        "case_count": len(rows),
        "scan_input_tree_sha256": actual_hash,
        "ground_truth_opened": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare or verify the frozen M15 E02 real-Skill corpus")
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    prepare.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    verify = subparsers.add_parser("verify-scan-inputs")
    verify.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "prepare":
        result = materialize(args.config.resolve(), args.output.resolve())
    else:
        result = verify_scan_inputs(args.output.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
