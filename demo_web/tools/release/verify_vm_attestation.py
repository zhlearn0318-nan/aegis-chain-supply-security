from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

EXPECTED_PROVIDERS = {
    "virtualbox",
    "vmware",
    "qemu-kvm",
    "parallels",
    "xen",
    "hyper-v-or-windows-sandbox",
}


class AttestationError(ValueError):
    """Raised when the clean Windows VM attestation is incomplete or contradictory."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def integrity_file(path: Path, algorithm: str = "sha512") -> str:
    if algorithm != "sha512":
        raise AttestationError(f"Unsupported integrity algorithm: {algorithm}")
    digest = hashlib.sha512(path.read_bytes()).digest()
    return f"sha512-{base64.b64encode(digest).decode('ascii')}"


def current_machine_guid_sha256() -> str:
    if sys.platform != "win32":
        raise AttestationError("Real Windows VM verification must run on Windows.")
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
    except (OSError, ImportError) as exc:
        raise AttestationError(
            f"Cannot read the current Windows machine identity: {exc}"
        ) from exc
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def parse_attestation_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise AttestationError(f"{label} is missing.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError(f"{label} is malformed.") from exc
    if parsed.tzinfo is None:
        raise AttestationError(f"{label} must include a timezone.")
    return parsed.astimezone(timezone.utc)


def normalized_text_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_remote(value: str) -> str:
    return value.strip().rstrip("/").lower()


def run_git(git: Path, repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [str(git), "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise AttestationError(
            f"git {' '.join(arguments)} failed: {(completed.stderr or completed.stdout).strip()}"
        )
    return completed.stdout.strip()


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttestationError(f"{label} must be an object.")
    return value


def validate_attestation(
    *,
    attestation_path: Path,
    project_root: Path,
    expected_commit: str,
    expected_ref: str,
    repository_url: str,
) -> dict[str, Any]:
    attestation_path = attestation_path.resolve(strict=True)
    project_root = project_root.resolve(strict=True)
    if attestation_path == project_root or project_root in attestation_path.parents:
        raise AttestationError(
            "VM attestation must be stored outside the cloned repository."
        )
    try:
        payload = json.loads(attestation_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestationError(f"Cannot read VM attestation: {exc}") from exc
    payload = require_mapping(payload, "attestation")
    if payload.get("schema_version") != "1.0" or payload.get("status") != "completed":
        raise AttestationError("Unsupported or incomplete VM attestation.")

    vm = require_mapping(payload.get("virtual_machine"), "virtual_machine")
    provider = vm.get("provider")
    if vm.get("proof_accepted") is not True or provider not in EXPECTED_PROVIDERS:
        raise AttestationError(
            "Attestation does not prove a supported real VM provider."
        )
    if not vm.get("manufacturer") or not vm.get("model"):
        raise AttestationError("VM manufacturer/model evidence is missing.")
    machine_hash = vm.get("machine_guid_sha256")
    if not isinstance(machine_hash, str) or len(machine_hash) != 64:
        raise AttestationError("Hashed VM identity is missing or malformed.")
    if machine_hash.lower() != current_machine_guid_sha256():
        raise AttestationError("Attestation belongs to a different Windows machine.")

    repository = require_mapping(payload.get("repository"), "repository")
    expected_commit = expected_commit.lower()
    expected_repository = normalize_remote(repository_url)
    repository_checks = {
        "fresh_clone": repository.get("fresh_clone") is True,
        "target_preexisted": repository.get("target_preexisted") is False,
        "url": normalize_remote(str(repository.get("url", ""))) == expected_repository,
        "ref": repository.get("ref") == expected_ref,
        "remote_commit": str(repository.get("remote_commit", "")).lower()
        == expected_commit,
        "checkout_commit": str(repository.get("checkout_commit", "")).lower()
        == expected_commit,
        "initial_status": repository.get("initial_status") == "",
        "preexisting_generated_paths": repository.get("preexisting_generated_paths")
        == [],
        "path": Path(str(repository.get("path", ""))).resolve(strict=True)
        == project_root,
    }
    failed_repository_checks = [
        key for key, passed in repository_checks.items() if not passed
    ]
    if failed_repository_checks:
        raise AttestationError(
            f"Fresh-clone attestation checks failed: {failed_repository_checks}"
        )
    clone_started = parse_attestation_time(
        repository.get("clone_started_at"), "clone_started_at"
    )
    clone_completed = parse_attestation_time(
        repository.get("clone_completed_at"), "clone_completed_at"
    )
    now = datetime.now(timezone.utc)
    if (
        clone_completed < clone_started
        or clone_completed - clone_started > timedelta(hours=2)
        or clone_completed < now - timedelta(hours=12)
        or clone_completed > now + timedelta(minutes=5)
    ):
        raise AttestationError(
            "Fresh-clone attestation timestamps are stale or contradictory."
        )

    negative = require_mapping(payload.get("negative_control"), "negative_control")
    negative_output = require_mapping(negative.get("output"), "negative_control.output")
    checks = negative_output.get("checks")
    if (
        negative.get("prebootstrap_preflight_exit") == 0
        or negative.get("prebootstrap_ready") is not False
        or int(negative.get("prebootstrap_required_failures", 0)) < 2
        or not isinstance(checks, list)
    ):
        raise AttestationError(
            "Pre-bootstrap negative control did not fail as required."
        )
    check_status = {
        item.get("id"): item.get("status")
        for item in checks
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if (
        check_status.get("skill_python") != "FAIL"
        or check_status.get("mcp_python") != "FAIL"
    ):
        raise AttestationError(
            "Negative control did not prove both scanner runtimes absent."
        )

    manifest_path = project_root / "demo_web/release_vm/toolchain.windows-x64.json"
    controller_path = (
        project_root / "demo_web/release_vm/Initialize-AegisAcceptanceGuest.ps1"
    )
    if payload.get("toolchain_manifest_sha256") != normalized_text_sha256(
        manifest_path
    ):
        raise AttestationError("Toolchain manifest differs from the cloned commit.")
    if payload.get("controller_sha256") != normalized_text_sha256(controller_path):
        raise AttestationError("Guest controller differs from the cloned commit.")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_downloads = {
        item["id"]: item
        for item in manifest.get("artifacts", [])
        if isinstance(item, dict)
    }
    expected_downloads.update(
        {
            item["id"]: item
            for item in manifest.get("package_managers", [])
            if isinstance(item, dict)
        }
    )
    toolchain = require_mapping(payload.get("toolchain"), "toolchain")
    downloads = toolchain.get("downloads")
    if not isinstance(downloads, list):
        raise AttestationError("Verified tool downloads are missing.")
    observed_downloads = {
        item.get("id"): item for item in downloads if isinstance(item, dict)
    }
    if set(observed_downloads) != set(expected_downloads):
        raise AttestationError(
            "Verified download set differs from the toolchain manifest."
        )
    for artifact_id, expected in expected_downloads.items():
        observed = observed_downloads.get(artifact_id)
        if not isinstance(observed, dict):
            raise AttestationError(f"Verified download is missing: {artifact_id}")
        expected_url = expected.get("url", expected.get("tarball"))
        if (
            observed.get("verified") is not True
            or observed.get("version") != expected.get("version")
            or observed.get("url") != expected_url
            or observed.get("license") != expected.get("license")
        ):
            raise AttestationError(f"Verified download metadata changed: {artifact_id}")
        download_path = Path(str(observed.get("path", ""))).resolve(strict=True)
        if project_root == download_path or project_root in download_path.parents:
            raise AttestationError(
                f"Verified download is inside the cloned repository: {artifact_id}"
            )
        if download_path.name != expected.get("file"):
            raise AttestationError(f"Verified download filename changed: {artifact_id}")
        if "sha256" in expected:
            if observed.get("sha256") != expected.get("sha256") or sha256_file(
                download_path
            ) != expected.get("sha256"):
                raise AttestationError(f"Verified download hash changed: {artifact_id}")
        elif "integrity" in expected:
            if observed.get("integrity") != expected.get("integrity") or integrity_file(
                download_path
            ) != expected.get("integrity"):
                raise AttestationError(
                    f"Verified package integrity changed: {artifact_id}"
                )
        else:
            raise AttestationError(
                f"No supported integrity value exists: {artifact_id}"
            )
    package_manager = manifest["package_managers"][0]
    pnpm = require_mapping(toolchain.get("pnpm"), "toolchain.pnpm")
    if pnpm.get("version") != package_manager.get("version") or pnpm.get(
        "integrity"
    ) != package_manager.get("integrity"):
        raise AttestationError(
            "pnpm version/integrity differs from the toolchain manifest."
        )

    git_data = require_mapping(toolchain.get("git"), "toolchain.git")
    git = Path(str(git_data.get("path", ""))).resolve(strict=True)
    actual_commit = run_git(git, project_root, "rev-parse", "HEAD").lower()
    actual_origin = normalize_remote(
        run_git(git, project_root, "remote", "get-url", "origin")
    )
    actual_status = run_git(
        git, project_root, "status", "--porcelain=v1", "--untracked-files=no"
    )
    if actual_commit != expected_commit:
        raise AttestationError(
            f"Current checkout is {actual_commit}, expected {expected_commit}."
        )
    if actual_origin != expected_repository:
        raise AttestationError(
            "Current origin differs from the attested private repository."
        )
    if actual_status:
        raise AttestationError("Tracked files changed after the fresh clone.")

    return {
        "schema_version": "1.0",
        "status": "completed",
        "provider": provider,
        "expected_commit": expected_commit,
        "expected_ref": expected_ref,
        "repository_url": repository_url,
        "fresh_clone": True,
        "negative_control_passed": True,
        "tool_downloads_verified": len(expected_downloads),
        "attestation_sha256": sha256_file(attestation_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a clean Windows VM attestation."
    )
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-ref", required=True)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = validate_attestation(
            attestation_path=args.attestation,
            project_root=args.project_root,
            expected_commit=args.expected_commit,
            expected_ref=args.expected_ref,
            repository_url=args.repository_url,
        )
    except (AttestationError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
