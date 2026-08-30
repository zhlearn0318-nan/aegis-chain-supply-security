from __future__ import annotations

import stat
import zipfile
from pathlib import Path

import pytest

from backend import uploaded_skill_admission as admission
from backend.uploaded_skill_admission import (
    UploadedSkillError,
    prepare_uploaded_skill,
    scan_prepared_skill,
    validate_target_name,
    verify_prepared_skill,
)


def session(uploads: Path) -> Path:
    uploads.mkdir()
    root = uploads / ("a" * 32)
    (root / "incoming").mkdir(parents=True)
    return root


def write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
        for name, content in members.items():
            package.writestr(name, content)


def test_prepares_zip_with_one_top_level_directory(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads"
    root = session(uploads)
    write_zip(
        root / "incoming" / "upload.zip",
        {
            "weather/SKILL.md": b"---\nname: weather-safe\ndescription: test\n---\n",
            "weather/run.py": b"print('ok')\n",
        },
    )

    prepared = prepare_uploaded_skill(root, uploads, "zip")

    assert prepared.root.name == "weather"
    assert prepared.file_count == 2
    assert prepared.total_bytes > 0
    assert prepared.suggested_name == "weather-safe"
    assert len(prepared.source_tree_sha256) == 64


@pytest.mark.parametrize(
    "member",
    ["../escape.txt", "/absolute.txt", "CON/file.txt", "bad:name.txt"],
)
def test_zip_rejects_unsafe_windows_paths(tmp_path: Path, member: str) -> None:
    uploads = tmp_path / "uploads"
    root = session(uploads)
    write_zip(
        root / "incoming" / "upload.zip",
        {"SKILL.md": b"---\nname: safe\n---\n", member: b"bad"},
    )

    with pytest.raises(UploadedSkillError, match="路径|文件名"):
        prepare_uploaded_skill(root, uploads, "zip")

    assert not (tmp_path / "escape.txt").exists()


def test_zip_rejects_symlink_member(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads"
    root = session(uploads)
    archive = root / "incoming" / "upload.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("SKILL.md", "---\nname: safe\n---\n")
        linked = zipfile.ZipInfo("linked.py")
        linked.create_system = 3
        linked.external_attr = (stat.S_IFLNK | 0o777) << 16
        package.writestr(linked, "outside.py")

    with pytest.raises(UploadedSkillError, match="符号链接"):
        prepare_uploaded_skill(root, uploads, "zip")


def test_zip_uses_declared_expanded_limit_before_extracting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admission, "MAX_EXPANDED_BYTES", 16)
    uploads = tmp_path / "uploads"
    root = session(uploads)
    write_zip(
        root / "incoming" / "upload.zip",
        {"SKILL.md": b"x" * 17},
    )

    with pytest.raises(UploadedSkillError, match="200 MB"):
        prepare_uploaded_skill(root, uploads, "zip")


def test_folder_upload_collapses_browser_selected_directory(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads"
    root = session(uploads)
    selected = root / "incoming" / "folder" / "local-skill"
    selected.mkdir(parents=True)
    (selected / "SKILL.md").write_text("---\nname: local-skill\n---\n", encoding="utf-8")

    prepared = prepare_uploaded_skill(root, uploads, "folder")

    assert prepared.root == selected.resolve()
    assert prepared.suggested_name == "local-skill"


def test_session_must_be_direct_child_of_controlled_upload_root(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    outside = tmp_path / ("b" * 32)
    outside.mkdir()

    with pytest.raises(UploadedSkillError, match="受控暂存区"):
        prepare_uploaded_skill(outside, uploads, "folder")


def test_verify_revokes_install_eligibility_after_content_change(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads"
    root = session(uploads)
    skill = root / "incoming" / "folder"
    skill.mkdir()
    manifest = skill / "SKILL.md"
    manifest.write_text("---\nname: stable\n---\n", encoding="utf-8")
    prepared = prepare_uploaded_skill(root, uploads, "folder")

    verify_prepared_skill(prepared.root, prepared.source_tree_sha256)
    manifest.write_text("---\nname: changed\n---\n", encoding="utf-8")

    with pytest.raises(UploadedSkillError, match="扫描后发生变化"):
        verify_prepared_skill(prepared.root, prepared.source_tree_sha256)


@pytest.mark.parametrize("name", ["../bad", "a/b", "con", "a" * 65])
def test_target_name_is_strict(name: str) -> None:
    with pytest.raises(UploadedSkillError):
        validate_target_name(name)


def test_target_name_normalizes_uppercase_user_input() -> None:
    assert validate_target_name("Safe-Skill") == "safe-skill"


def test_scan_requires_allow_and_valid_audit_chain_for_install_eligibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    uploads = tmp_path / "uploads"
    root = session(uploads)
    skill = root / "incoming" / "folder"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: safe\n---\n", encoding="utf-8")
    prepared = prepare_uploaded_skill(root, uploads, "folder")
    monkeypatch.setattr(
        admission,
        "evaluate_install_request",
        lambda *_args, **_kwargs: {
            "decision": "allow",
            "reason": "clean",
            "findings": [{"ruleId": "AEGIS_DYNAMIC_EXECUTION_CLEAN", "severity": "info"}],
        },
    )
    monkeypatch.setattr(admission, "verify_install_policy_audit", lambda: {"valid": True, "rows": 1})
    monkeypatch.setattr(
        admission,
        "read_recent_install_policy_audits",
        lambda limit: [{"target_name": "safe", "source_tree_sha256": prepared.source_tree_sha256}],
    )

    result = scan_prepared_skill(prepared, "safe")

    assert result["decision"] == "ALLOW"
    assert result["install_eligible"] is True
    assert result["audit"] is not None
