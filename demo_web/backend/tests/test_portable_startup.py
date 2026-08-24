from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEMO_ROOT = PROJECT_ROOT / "demo_web"


def _powershell() -> str:
    discovered = shutil.which("pwsh") or shutil.which("powershell")
    if discovered:
        return discovered
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    fallback = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if fallback.is_file():
        return str(fallback)
    raise AssertionError("PowerShell is required by the Windows startup contract")


def test_active_startup_files_do_not_contain_developer_absolute_paths() -> None:
    files = (
        PROJECT_ROOT / "bootstrap_runtimes.ps1",
        DEMO_ROOT / "preflight.ps1",
        DEMO_ROOT / "start_demo.ps1",
        DEMO_ROOT / "scripts" / "portable_runtime.ps1",
    )
    forbidden = (r"C:\Users\23684", "codex-runtimes", r"F:\揭榜挂帅")

    for path in files:
        content = path.read_text(encoding="utf-8")
        for marker in forbidden:
            assert marker not in content, f"{path.name} contains developer path: {marker}"


def test_startup_uses_preflight_frozen_frontend_and_v1_health_contract() -> None:
    startup = (DEMO_ROOT / "start_demo.ps1").read_text(encoding="utf-8")
    package = json.loads((DEMO_ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))

    assert "preflight.ps1" in startup
    assert "Resolve-AegisPackageManager" in startup
    assert '"install", "--frozen-lockfile"' in startup
    assert "/api/v1/health" in startup
    assert "/api/health" not in startup
    assert "[ValidateRange(1024, 65535)][int]$Port = 8000" in startup
    assert package["packageManager"] == "pnpm@11.19.0"


def test_bootstrap_locks_cisco_sources_and_refuses_automatic_overwrite() -> None:
    bootstrap = (PROJECT_ROOT / "bootstrap_runtimes.ps1").read_text(encoding="utf-8")

    assert "https://github.com/cisco-ai-defense/skill-scanner.git" in bootstrap
    assert "4dee90371890ff23e1b21ea974e02847eacaa464" in bootstrap
    assert "https://github.com/cisco-ai-defense/mcp-scanner.git" in bootstrap
    assert "51966cce214ae057e69c3a672307911f5026e255" in bootstrap
    assert "--require-hashes" in bootstrap
    assert "demo_web\\backend\\requirements.lock" in bootstrap
    assert "demo_web\\backend\\runtime-security.lock" in bootstrap
    assert "verify_installed_python_lock.py" in bootstrap
    assert "Hash-locked project backend installation failed" in bootstrap
    assert "Hash-locked shared-runtime security overlay failed" in bootstrap
    assert "SkillWheelSha256" in bootstrap
    assert "McpWheelSha256" in bootstrap
    assert "Offline wheel SHA-256 mismatch" in bootstrap
    assert '"verified-" + $Definition.Id.ToLowerInvariant()' in bootstrap
    assert "will not overwrite it" in bootstrap
    assert "Remove-Item" not in bootstrap


def test_cisco_reproduction_rejects_dependency_audit_fail_open() -> None:
    reproduction = (PROJECT_ROOT / "run_cisco_reproduction.ps1").read_text(encoding="utf-8")

    assert "Invoke-VerifiedMcpDependencyScan" in reproduction
    assert "pip-audit exited|produced no JSON|pip-audit error" in reproduction
    assert "was rejected fail-closed" in reproduction
    assert "$TotalFindings -le 0" in reproduction
    assert "--vulnerability-service osv" in reproduction


def test_preflight_resolves_corepack_without_original_user_profile(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_corepack = fake_bin / "corepack.cmd"
    fake_corepack.write_text(
        "@echo off\r\n"
        'if "%1"=="pnpm" if "%2"=="--version" (echo 11.19.0& exit /b 0)\r\n'
        "exit /b 2\r\n",
        encoding="ascii",
    )

    env = os.environ.copy()
    system_root = Path(env.get("SystemRoot", r"C:\Windows"))
    env["PATH"] = os.pathsep.join((str(fake_bin), str(system_root / "System32"), str(system_root)))
    env["USERPROFILE"] = r"C:\Users\aegis-clean-user"
    env.pop("AEGIS_PNPM_COMMAND", None)

    completed = subprocess.run(
        [
            _powershell(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(DEMO_ROOT / "preflight.ps1"),
            "-SkipDynamic",
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    result = json.loads(completed.stdout)
    checks = {item["id"]: item for item in result["checks"]}
    assert result["ready"] is True
    assert result["required_failures"] == 0
    assert checks["package_manager"]["status"] == "PASS"
    assert checks["package_manager"]["message"] == "corepack pnpm"
    assert checks["skill_version"]["message"] == "2.0.13.dev3+g4dee90371"
    assert checks["mcp_version"]["message"] == "4.8.2"
    assert checks["backend_lock_match"]["status"] == "PASS"
    assert checks["runtime_security_lock_match"]["status"] == "PASS"


def test_required_dynamic_preflight_fails_closed_without_admin_token() -> None:
    env = os.environ.copy()
    env.pop("AEGIS_ADMIN_TOKEN", None)

    completed = subprocess.run(
        [
            _powershell(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(DEMO_ROOT / "preflight.ps1"),
            "-RequireDynamic",
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )

    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    checks = {item["id"]: item for item in result["checks"]}
    assert result["ready"] is False
    assert result["required_failures"] >= 1
    assert checks["admin_token"]["required"] is True
    assert checks["admin_token"]["status"] == "FAIL"
