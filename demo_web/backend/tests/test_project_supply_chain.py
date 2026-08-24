from __future__ import annotations

import json
from pathlib import Path

from tools.supply_chain.audit_project_supply_chain import (
    Component,
    build_sbom,
    parse_pnpm_lock,
    parse_python_lock,
    scan_repository_secrets,
)
from tools.supply_chain.verify_installed_python_lock import verify


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEMO_ROOT = PROJECT_ROOT / "demo_web"


def test_python_runtime_lock_is_hashed_exact_and_installed() -> None:
    lock = DEMO_ROOT / "backend" / "requirements.lock"
    packages = parse_python_lock(lock)

    assert packages
    assert all(item["hashes"] for item in packages)
    assert {(item["name"], item["version"]) for item in packages}.issuperset(
        {
            ("fastapi", "0.141.1"),
            ("python-multipart", "0.0.32"),
            ("starlette", "1.3.1"),
            ("click", "8.3.3"),
            ("idna", "3.15"),
        }
    )
    assert verify(lock)["decision"] == "PASS"

    dev_packages = parse_python_lock(DEMO_ROOT / "backend" / "requirements-dev.lock")
    assert all(item["hashes"] for item in dev_packages)
    assert ("pytest", "9.0.3") in {(item["name"], item["version"]) for item in dev_packages}

    security_lock = DEMO_ROOT / "backend" / "runtime-security.lock"
    security_packages = parse_python_lock(security_lock)
    assert len(security_packages) == 17
    assert all(item["hashes"] for item in security_packages)
    assert verify(security_lock)["decision"] == "PASS"


def test_frontend_direct_dependencies_and_lock_integrity_are_exact() -> None:
    package = json.loads((DEMO_ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    direct = {**package["dependencies"], **package["devDependencies"]}
    lock = parse_pnpm_lock(DEMO_ROOT / "frontend" / "pnpm-lock.yaml")
    workspace = (DEMO_ROOT / "frontend" / "pnpm-workspace.yaml").read_text(encoding="utf-8")

    assert direct == {
        "react": "19.2.8",
        "react-dom": "19.2.8",
        "@vitejs/plugin-react": "6.0.5",
        "vite": "8.2.0",
    }
    assert package["packageManager"] == "pnpm@11.19.0"
    assert lock and all(item["integrity"] for item in lock)
    assert not any(item["name"] == "nanoid" and item["version"] == "3.3.16" for item in lock)
    assert "'nanoid@<3.3.18': 3.3.18" in workspace
    assert "minimumReleaseAge: 1440" in workspace


def test_repository_legal_files_and_cyclonedx_sbom_are_present() -> None:
    assert (PROJECT_ROOT / "LICENSE").is_file()
    assert (PROJECT_ROOT / "THIRD_PARTY_NOTICES.md").is_file()
    sbom = json.loads((PROJECT_ROOT / "PROJECT_SBOM.cdx.json").read_text(encoding="utf-8"))

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert sbom["metadata"]["component"]["name"] == "aegis-chain-supply-security"
    assert len(sbom["components"]) >= 40


def test_sbom_generation_is_deterministic() -> None:
    components = [
        Component("python", "fastapi", "0.141.1", "MIT"),
        Component("node", "react", "19.2.8", "MIT", "sha512-YWJj"),
    ]
    hashes = {"python-lock": "a" * 64, "pnpm-lock": "b" * 64}

    assert build_sbom(components, hashes) == build_sbom(list(reversed(components)), hashes)


def test_secret_scan_redacts_detected_value(monkeypatch, tmp_path: Path) -> None:
    value = "fixture-Ab3Def5Gh7Jk9Lm2Np4Qr6St8Uv0Wx"
    candidate = tmp_path / "candidate.txt"
    candidate.write_text(f'api_key = "{value}"\n', encoding="utf-8")
    monkeypatch.setattr(
        "tools.supply_chain.audit_project_supply_chain._git_files",
        lambda _root: [candidate],
    )

    report = scan_repository_secrets(tmp_path, ())

    assert report["verified_leaks"] == 1
    assert value not in json.dumps(report)
    assert len(report["findings"][0]["fingerprint"]) == 16


def test_current_repository_secret_scan_has_no_verified_leaks() -> None:
    policy = json.loads(
        (DEMO_ROOT / "config" / "project_supply_chain_policy.json").read_text(encoding="utf-8")
    )

    report = scan_repository_secrets(PROJECT_ROOT, policy["synthetic_secret_markers"])

    assert report["verified_leaks"] == 0
