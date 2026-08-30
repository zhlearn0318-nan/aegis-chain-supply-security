from __future__ import annotations

import os
import re
import shutil
import stat
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .install_policy_audit import (
    read_recent_install_policy_audits,
    record_install_policy_audit,
    verify_install_policy_audit,
)
from .openclaw_install_policy import (
    SourceTreeLimits,
    evaluate_install_request,
    hash_source_tree,
)


MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EXPANDED_BYTES = 200 * 1024 * 1024
MAX_FILES = 5_000
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_PATH_LENGTH = 240
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
TARGET_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul", "clock$",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


class UploadedSkillError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PreparedSkill:
    root: Path
    source_tree_sha256: str
    file_count: int
    total_bytes: int
    suggested_name: str


def validate_target_name(value: Any) -> str:
    name = str(value or "").strip().lower()
    if not TARGET_NAME.fullmatch(name) or name in WINDOWS_RESERVED:
        raise UploadedSkillError(
            "TARGET_NAME_INVALID",
            "Skill 安装名称仅允许 1-64 位小写字母、数字、点、下划线和连字符。",
        )
    return name


def _safe_relative_path(value: str) -> PurePosixPath:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value) or "\\" in value:
        raise UploadedSkillError("ARCHIVE_PATH_INVALID", "压缩包包含无效路径。")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts:
        raise UploadedSkillError("ARCHIVE_PATH_INVALID", "压缩包包含绝对路径。")
    for part in path.parts:
        if part in {"", ".", ".."} or part.endswith((" ", ".")):
            raise UploadedSkillError("ARCHIVE_PATH_INVALID", "压缩包包含路径穿越或 Windows 非法路径。")
        if any(character in part for character in '<>:"|?*'):
            raise UploadedSkillError("ARCHIVE_PATH_INVALID", "压缩包包含 Windows 非法文件名。")
        if part.split(".", 1)[0].casefold() in WINDOWS_RESERVED:
            raise UploadedSkillError("ARCHIVE_PATH_INVALID", "压缩包包含 Windows 保留文件名。")
    if len(path.as_posix()) > MAX_PATH_LENGTH:
        raise UploadedSkillError("ARCHIVE_PATH_TOO_LONG", "压缩包内部路径超过 240 字符。")
    return path


def _ensure_session_root(session_root: Path, uploads_root: Path) -> Path:
    uploads = uploads_root.resolve(strict=True)
    root = session_root.resolve(strict=True)
    try:
        relative = root.relative_to(uploads)
    except ValueError as exc:
        raise UploadedSkillError("SESSION_PATH_DENIED", "上传会话不在受控暂存区内。") from exc
    if len(relative.parts) != 1 or not re.fullmatch(r"[0-9a-f]{32}", relative.name):
        raise UploadedSkillError("SESSION_PATH_DENIED", "上传会话标识无效。")
    if root.is_symlink():
        raise UploadedSkillError("SESSION_PATH_DENIED", "上传会话不能是符号链接。")
    return root


def _tree_statistics(root: Path) -> tuple[int, int]:
    count = 0
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise UploadedSkillError("SOURCE_LINK_DENIED", "Skill 包含符号链接或目录联接。")
        if path.is_file():
            count += 1
            size = path.stat().st_size
            total += size
            if count > MAX_FILES:
                raise UploadedSkillError("SOURCE_FILE_LIMIT", "Skill 文件数量超过 5,000。")
            if size > MAX_FILE_BYTES:
                raise UploadedSkillError("SOURCE_FILE_SIZE_LIMIT", "Skill 包含超过 50 MB 的单个文件。")
            if total > MAX_EXPANDED_BYTES:
                raise UploadedSkillError("SOURCE_TOTAL_SIZE_LIMIT", "Skill 解压后总大小超过 200 MB。")
    return count, total


def _select_skill_root(container: Path) -> Path:
    direct = container / "SKILL.md"
    if direct.is_file():
        return container
    children = [item for item in container.iterdir() if item.name not in {"__MACOSX", ".DS_Store"}]
    directories = [item for item in children if item.is_dir() and not item.is_symlink()]
    files = [item for item in children if item.is_file()]
    if len(directories) == 1 and not files and (directories[0] / "SKILL.md").is_file():
        return directories[0]
    raise UploadedSkillError(
        "SKILL_MANIFEST_MISSING",
        "Skill 根目录必须包含 SKILL.md；压缩包可额外包含一层顶级目录。",
    )


def _suggest_name(root: Path) -> str:
    fallback = re.sub(r"[^a-z0-9._-]+", "-", root.name.casefold()).strip("-._")
    try:
        text = (root / "SKILL.md").read_text(encoding="utf-8", errors="strict")[:16_384]
    except (OSError, UnicodeDecodeError):
        text = ""
    match = re.search(r"(?mi)^name\s*:\s*['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?\s*$", text)
    candidate = (match.group(1) if match else fallback or "uploaded-skill").lower()
    candidate = candidate[:64].rstrip("-._")
    return candidate if TARGET_NAME.fullmatch(candidate) else "uploaded-skill"


def _extract_zip(archive: Path, destination: Path) -> None:
    size = archive.stat().st_size
    if size < 1 or size > MAX_ARCHIVE_BYTES:
        raise UploadedSkillError("ARCHIVE_SIZE_LIMIT", "ZIP 压缩包必须大于 0 且不超过 50 MB。")
    partial = destination.with_name(f"{destination.name}.partial-{uuid.uuid4().hex}")
    partial.mkdir(parents=False, exist_ok=False)
    seen: set[str] = set()
    files = 0
    expanded = 0
    try:
        try:
            package = zipfile.ZipFile(archive)
        except (OSError, zipfile.BadZipFile) as exc:
            raise UploadedSkillError("ARCHIVE_INVALID", "上传文件不是有效 ZIP 压缩包。") from exc
        with package:
            for info in package.infolist():
                relative = _safe_relative_path(info.filename.rstrip("/"))
                normalized = relative.as_posix().casefold()
                if normalized in seen:
                    raise UploadedSkillError("ARCHIVE_DUPLICATE_PATH", "ZIP 包含重复或大小写冲突路径。")
                seen.add(normalized)
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode and stat.S_ISLNK(mode):
                    raise UploadedSkillError("ARCHIVE_LINK_DENIED", "ZIP 包含符号链接。")
                if info.flag_bits & 0x1:
                    raise UploadedSkillError("ARCHIVE_ENCRYPTED", "不接受加密 ZIP。")
                if info.compress_type not in ALLOWED_COMPRESSION:
                    raise UploadedSkillError("ARCHIVE_COMPRESSION_DENIED", "ZIP 使用了不支持的压缩算法。")
                target = partial.joinpath(*relative.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                files += 1
                expanded += info.file_size
                if files > MAX_FILES:
                    raise UploadedSkillError("SOURCE_FILE_LIMIT", "Skill 文件数量超过 5,000。")
                if info.file_size > MAX_FILE_BYTES:
                    raise UploadedSkillError("SOURCE_FILE_SIZE_LIMIT", "Skill 包含超过 50 MB 的单个文件。")
                if expanded > MAX_EXPANDED_BYTES:
                    raise UploadedSkillError("SOURCE_TOTAL_SIZE_LIMIT", "Skill 解压后总大小超过 200 MB。")
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.open(info, "r") as source, target.open("xb") as output:
                    copied = shutil.copyfileobj(source, output, length=64 * 1024)
                if target.stat().st_size != info.file_size:
                    raise UploadedSkillError("ARCHIVE_SIZE_MISMATCH", "ZIP 解压文件大小与目录记录不一致。")
        if files < 1:
            raise UploadedSkillError("ARCHIVE_EMPTY", "ZIP 压缩包中没有文件。")
        partial.rename(destination)
    except Exception:
        shutil.rmtree(partial, ignore_errors=True)
        raise


def prepare_uploaded_skill(
    session_root: Path,
    uploads_root: Path,
    source_kind: str,
) -> PreparedSkill:
    session = _ensure_session_root(session_root, uploads_root)
    if source_kind == "zip":
        archive = session / "incoming" / "upload.zip"
        if not archive.is_file() or archive.is_symlink():
            raise UploadedSkillError("UPLOAD_INCOMPLETE", "ZIP 文件尚未完整上传。")
        prepared = session / "prepared"
        if prepared.exists():
            raise UploadedSkillError("SESSION_ALREADY_PREPARED", "该上传会话已经完成预处理。")
        _extract_zip(archive, prepared)
        container = prepared
    elif source_kind == "folder":
        container = session / "incoming" / "folder"
        if not container.is_dir() or container.is_symlink():
            raise UploadedSkillError("UPLOAD_INCOMPLETE", "本地文件夹尚未完整上传。")
    else:
        raise UploadedSkillError("SOURCE_KIND_INVALID", "仅支持 zip 或 folder 上传。")

    root = _select_skill_root(container).resolve(strict=True)
    count, total = _tree_statistics(root)
    if count < 1:
        raise UploadedSkillError("SOURCE_EMPTY", "Skill 目录中没有可扫描文件。")
    digest = hash_source_tree(
        root,
        SourceTreeLimits(
            max_files=MAX_FILES,
            max_total_bytes=MAX_EXPANDED_BYTES,
            max_file_bytes=MAX_FILE_BYTES,
        ),
    )
    return PreparedSkill(root, digest, count, total, _suggest_name(root))


def scan_prepared_skill(
    prepared: PreparedSkill,
    target_name: str,
    *,
    openclaw_version: str = "2026.7.1-2",
) -> dict[str, Any]:
    name = validate_target_name(target_name)
    payload = {
        "protocolVersion": 1,
        "openclawVersion": openclaw_version,
        "targetType": "skill",
        "targetName": name,
        "sourcePath": str(prepared.root),
        "sourcePathKind": "directory",
        "source": {"kind": "browser-upload", "mutable": False},
        "origin": {"type": "aegis-admission-ui"},
        "request": {"kind": "skill-preflight", "mode": "scan-only"},
    }
    response = evaluate_install_request(
        payload,
        audit_recorder=record_install_policy_audit,
    )
    integrity = verify_install_policy_audit()
    audits = read_recent_install_policy_audits(limit=5)
    audit = next(
        (
            item
            for item in audits
            if item.get("target_name") == name
            and item.get("source_tree_sha256") == prepared.source_tree_sha256
        ),
        None,
    )
    decision = str(response.get("decision") or "block").upper()
    return {
        "decision": decision,
        "install_eligible": decision == "ALLOW" and integrity.get("valid") is True,
        "reason": str(response.get("reason") or ""),
        "findings": response.get("findings") if isinstance(response.get("findings"), list) else [],
        "source_tree_sha256": prepared.source_tree_sha256,
        "file_count": prepared.file_count,
        "total_bytes": prepared.total_bytes,
        "suggested_name": prepared.suggested_name,
        "target_name": name,
        "audit": audit,
        "audit_integrity": integrity,
        "source_root": str(prepared.root),
    }


def verify_prepared_skill(root: Path, expected_sha256: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_sha256 or "")):
        raise UploadedSkillError("SOURCE_HASH_INVALID", "扫描会话中的内容指纹无效。")
    selected = _select_skill_root(root) if not (root / "SKILL.md").is_file() else root
    count, total = _tree_statistics(selected)
    actual = hash_source_tree(
        selected,
        SourceTreeLimits(MAX_FILES, MAX_EXPANDED_BYTES, MAX_FILE_BYTES),
    )
    if actual != expected_sha256:
        raise UploadedSkillError("SOURCE_CHANGED", "Skill 内容在扫描后发生变化，安装资格已撤销。")
    return {"source_tree_sha256": actual, "file_count": count, "total_bytes": total}
