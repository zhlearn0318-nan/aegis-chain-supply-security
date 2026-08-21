from __future__ import annotations

from pathlib import Path

import pytest

from backend import app as gateway
from backend.adapters.process import AdapterResult
from backend.analyzers.dependency_integrity import ANALYZER_ID, analyze_dependency_manifest
from backend.models import ScanJob
from backend.policy import evaluate_findings


HASH_A = "a" * 64
HASH_B = "b" * 64


def write_manifest(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text(content, encoding="utf-8")
    return path


def rule_ids(findings: list[dict]) -> set[str]:
    return {item["rule_id"] for item in findings}


def test_hashed_exact_lock_is_allow_and_generates_cyclonedx(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        f"requests==2.32.4 --hash=sha256:{HASH_A}\ncertifi==2025.8.3 --hash=sha256:{HASH_B}\n",
    )

    findings, analyzers, sbom = analyze_dependency_manifest(path)

    assert analyzers == [ANALYZER_ID]
    assert rule_ids(findings) == {"AEGIS_DEPENDENCY_INVENTORY_SUMMARY"}
    assert evaluate_findings(findings).decision.value == "ALLOW"
    assert sbom["bomFormat"] == "CycloneDX"
    assert [item["name"] for item in sbom["components"]] == ["certifi", "requests"]
    assert sbom["components"][1]["purl"] == "pkg:pypi/requests@2.32.4"


@pytest.mark.parametrize("entry", ["requests", "requests>=2", "requests~=2.32", "requests<3"])
def test_unpinned_versions_require_review(tmp_path: Path, entry: str) -> None:
    findings, _, _ = analyze_dependency_manifest(write_manifest(tmp_path, entry + "\n"))

    assert "AEGIS_DEPENDENCY_VERSION_UNPINNED" in rule_ids(findings)
    assert "AEGIS_DEPENDENCY_HASHES_MISSING" in rule_ids(findings)
    assert evaluate_findings(findings).decision.value == "REVIEW"


def test_exact_pin_without_hash_requires_review(tmp_path: Path) -> None:
    findings, _, sbom = analyze_dependency_manifest(write_manifest(tmp_path, "flask==3.1.1\n"))

    assert "AEGIS_DEPENDENCY_HASHES_MISSING" in rule_ids(findings)
    assert sbom["metadata"]["properties"][-1]["value"] == "false"


@pytest.mark.parametrize(
    "entry",
    [
        "internal-lib @ https://packages.invalid/internal.whl",
        "git+https://git.invalid/team/repo.git@main#egg=internal-lib",
        "-e ../internal-lib",
    ],
)
def test_unverified_direct_sources_block(tmp_path: Path, entry: str) -> None:
    findings, _, _ = analyze_dependency_manifest(write_manifest(tmp_path, entry + "\n"))

    assert "AEGIS_DEPENDENCY_DIRECT_SOURCE_UNVERIFIED" in rule_ids(findings)
    assert evaluate_findings(findings).decision.value == "BLOCK"
    assert "packages.invalid" not in " ".join(item["evidence"] for item in findings)


def test_extra_index_blocks_dependency_confusion_path(tmp_path: Path) -> None:
    content = "--extra-index-url https://public.invalid/simple\ninternal-auth==1.2.3\n"
    findings, _, _ = analyze_dependency_manifest(write_manifest(tmp_path, content))

    assert "AEGIS_DEPENDENCY_EXTRA_INDEX" in rule_ids(findings)
    assert evaluate_findings(findings).decision.value == "BLOCK"


@pytest.mark.parametrize(
    "option",
    ["--index-url http://mirror.invalid/simple", "--trusted-host mirror.invalid"],
)
def test_insecure_index_configuration_blocks(tmp_path: Path, option: str) -> None:
    findings, _, _ = analyze_dependency_manifest(write_manifest(tmp_path, option + "\n"))

    assert "AEGIS_DEPENDENCY_INSECURE_INDEX" in rule_ids(findings)
    assert evaluate_findings(findings).decision.value == "BLOCK"


def test_external_include_is_visible_coverage_gap(tmp_path: Path) -> None:
    findings, _, _ = analyze_dependency_manifest(write_manifest(tmp_path, "-r base.txt\n"))

    assert "AEGIS_DEPENDENCY_EXTERNAL_INCLUDE" in rule_ids(findings)
    assert evaluate_findings(findings).decision.value == "REVIEW"


@pytest.mark.parametrize("entry", ["-rbase.txt", "--constraint=constraints.txt"])
def test_compact_external_include_forms_are_visible(tmp_path: Path, entry: str) -> None:
    findings, _, _ = analyze_dependency_manifest(write_manifest(tmp_path, entry + "\n"))

    assert "AEGIS_DEPENDENCY_EXTERNAL_INCLUDE" in rule_ids(findings)


@pytest.mark.parametrize("entry", ["C:\\packages\\internal.whl", "internal-1.0-py3-none-any.whl", "--find-links https://packages.invalid/wheels"])
def test_alternative_or_local_distribution_sources_block(tmp_path: Path, entry: str) -> None:
    findings, _, _ = analyze_dependency_manifest(write_manifest(tmp_path, entry + "\n"))

    assert "AEGIS_DEPENDENCY_DIRECT_SOURCE_UNVERIFIED" in rule_ids(findings)
    assert evaluate_findings(findings).decision.value == "BLOCK"


def test_continuation_hashes_are_bound_to_component(tmp_path: Path) -> None:
    content = f"requests==2.32.4 \\\n+  --hash=sha256:{HASH_A} \\\n+  --hash=sha256:{HASH_B}\n"
    findings, _, sbom = analyze_dependency_manifest(write_manifest(tmp_path, content))

    assert rule_ids(findings) == {"AEGIS_DEPENDENCY_INVENTORY_SUMMARY"}
    assert len(sbom["components"][0]["hashes"]) == 2


def test_manifest_analysis_is_deterministic(tmp_path: Path) -> None:
    path = write_manifest(tmp_path, "requests==2.32.4\n")

    first = analyze_dependency_manifest(path)
    second = analyze_dependency_manifest(path)

    assert first == second


def test_binary_and_oversized_manifests_fail_closed(tmp_path: Path) -> None:
    binary = tmp_path / "binary.txt"
    binary.write_bytes(b"requests==1\x00hidden")
    with pytest.raises(ValueError, match="binary"):
        analyze_dependency_manifest(binary)

    oversized = tmp_path / "oversized.txt"
    oversized.write_bytes(b"a" * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match="1 MiB"):
        analyze_dependency_manifest(oversized)


def test_dependency_scan_integration_persists_sbom(monkeypatch, tmp_path: Path) -> None:
    path = write_manifest(tmp_path, "legacy-lib==1.0\n")

    class FakeAdapter:
        def scan(self, _path: Path) -> AdapterResult:
            return AdapterResult(report={"dependencies": [{"name": "legacy-lib", "version": "1.0", "vulns": []}]}, logs=["completed"])

    job = ScanJob(
        id="dependency-integration",
        created_at="2026-08-21T00:00:00+00:00",
        updated_at="2026-08-21T00:00:00+00:00",
        status="running",
        target_kind="dependency",
        source_kind="upload",
        display_name="requirements.txt",
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "DEPENDENCY_ADAPTER", FakeAdapter())
    monkeypatch.setattr(gateway, "save_job", lambda _job: None)

    gateway.scan_dependency_path(job, path)

    assert job["status"] == "completed"
    assert job["decision"] == "REVIEW"
    assert ANALYZER_ID in job["analyzers"]
    assert job["sbom"]["components"][0]["name"] == "legacy-lib"


def test_sbom_can_be_exported_and_absence_is_explicit(monkeypatch, tmp_path: Path) -> None:
    _, _, sbom = analyze_dependency_manifest(
        write_manifest(tmp_path, f"requests==2.32.4 --hash=sha256:{HASH_A}\n")
    )
    job = ScanJob(
        id="sbom-export",
        created_at="2026-08-21T00:00:00+00:00",
        updated_at="2026-08-21T00:00:00+00:00",
        status="completed",
        target_kind="dependency",
        source_kind="upload",
        display_name="requirements.txt",
        sbom=sbom,
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "load_job", lambda _job_id: job)

    response = gateway.export_scan(job["id"], format="sbom")

    assert response.media_type == "application/vnd.cyclonedx+json"
    assert "scan-sbom-export.cdx.json" in response.headers["Content-Disposition"]

    job["sbom"] = None
    with pytest.raises(gateway.GatewayHTTPException) as exc_info:
        gateway.export_scan(job["id"], format="sbom")
    assert exc_info.value.code.value == "SBOM_UNAVAILABLE"
