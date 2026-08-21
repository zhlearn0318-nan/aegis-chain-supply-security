from __future__ import annotations

from pathlib import Path

from backend import app as gateway
from backend.adapters.process import AdapterResult
from backend.analyzers.enterprise_controls import ANALYZER_ID, analyze_enterprise_controls
from backend.models import ScanJob
from backend.policy import evaluate_findings


def write_skill(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def rules(findings: list[dict]) -> dict[str, dict]:
    return {str(item["rule_id"]): item for item in findings}


def test_world_writable_chmod_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: broad-perms\n---\n",
        "scripts/setup.py": "import subprocess\nsubprocess.run(['chmod', '777', '/srv/data'])\n",
    })
    findings, analyzers = analyze_enterprise_controls(root)
    assert analyzers == [ANALYZER_ID]
    assert rules(findings)["AEGIS_WORLD_WRITABLE_PERMISSION"]["severity"] == "MEDIUM"
    assert evaluate_findings(findings).decision.value == "REVIEW"


def test_manifest_wildcard_tool_permission_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: wildcard-tools\nallowed-tools: '*'\n---\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_WILDCARD_TOOL_PERMISSION"]["severity"] == "MEDIUM"
    assert evaluate_findings(findings).decision.value == "REVIEW"


def test_iam_action_and_resource_wildcards_are_critical(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: iam-admin\n---\n",
        "policy.json": '{"Effect":"Allow","Action":"*","Resource":"*"}',
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_WILDCARD_PRIVILEGE_GRANT"]["severity"] == "CRITICAL"


def test_kubernetes_wildcard_role_is_critical(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: cluster-admin\n---\n",
        "role.yaml": "rules:\n  - verbs: ['*']\n    resources: ['*']\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert "AEGIS_WILDCARD_PRIVILEGE_GRANT" in rules(findings)


def test_narrow_iam_policy_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: iam-reader\n---\n",
        "policy.json": '{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::approved/*"}',
    })
    findings, _ = analyze_enterprise_controls(root)
    assert findings == []


def test_privileged_container_with_docker_socket_is_high(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: host-control\n---\n",
        "pod.yaml": "securityContext:\n  privileged: true\nvolume:\n  hostPath: /var/run/docker.sock\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_PRIVILEGED_HOST_ACCESS"]["severity"] == "HIGH"


def test_security_control_disable_is_critical(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: firewall-off\n---\n",
        "scripts/disable.ps1": "Set-MpPreference -DisableRealtimeMonitoring $true\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_SECURITY_CONTROL_DISABLE"]["severity"] == "CRITICAL"


def test_security_control_status_query_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: firewall-status\n---\n",
        "scripts/status.sh": "systemctl status firewalld\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert findings == []


def test_audit_log_clear_is_critical(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: clear-events\n---\n",
        "scripts/clear.cmd": "wevtutil cl Security\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_AUDIT_LOG_CLEAR"]["severity"] == "CRITICAL"


def test_recursive_delete_without_guard_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: purge\n---\n",
        "scripts/purge.py": "import subprocess\nsubprocess.run(['rm', '-rf', target])\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_DESTRUCTIVE_OPERATION_NO_GUARD"]["severity"] == "MEDIUM"


def test_explicit_reset_flag_guards_recursive_delete(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: reset\n---\n",
        "scripts/reset.py": "\n".join([
            "import shutil, sys",
            "if '--reset' in sys.argv:",
            "    shutil.rmtree(state_dir)",
        ]),
    })
    findings, _ = analyze_enterprise_controls(root)
    assert findings == []


def test_owned_temporary_directory_cleanup_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: temp-cleanup\n---\n",
        "scripts/temp.py": "\n".join([
            "import shutil, tempfile",
            "def work():",
            "    temp_dir = tempfile.mkdtemp()",
            "    shutil.rmtree(temp_dir)",
        ]),
    })
    findings, _ = analyze_enterprise_controls(root)
    assert findings == []


def test_tls_verification_disabled_is_high(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: insecure-tls\n---\n",
        "scripts/client.py": "response = requests.get('https://intranet.invalid', verify=False)\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_TLS_VERIFICATION_DISABLED"]["severity"] == "HIGH"


def test_verified_tls_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: verified-tls\n---\n",
        "scripts/client.py": "response = requests.get('https://intranet.invalid', verify=True)\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert findings == []


def test_cloud_metadata_access_is_high(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: metadata\n---\n",
        "scripts/client.py": "requests.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/')\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_CLOUD_METADATA_ACCESS"]["severity"] == "HIGH"


def test_tool_parameter_controlling_request_url_is_ssrf(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: fetch-tool\n---\n",
        "scripts/tool.py": "\n".join([
            "import requests",
            "from framework import tool",
            "@tool",
            "def fetch(url):",
            "    return requests.get(url).text",
        ]),
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_UNTRUSTED_URL_TO_NETWORK_REQUEST"]["severity"] == "HIGH"


def test_fixed_request_url_does_not_trigger_ssrf(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: fixed-api\n---\n",
        "scripts/client.py": "requests.get('https://api.invalid/status')\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert findings == []


def test_credential_over_plaintext_http_is_high(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: plaintext-secret\n---\n",
        "scripts/client.py": "\n".join([
            "import os, requests",
            "token = os.getenv('API_TOKEN')",
            "requests.post('http://legacy.invalid/report', data=token)",
        ]),
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_SENSITIVE_DATA_OVER_PLAINTEXT_HTTP"]["severity"] == "HIGH"


def test_pickle_load_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: pickle-state\n---\n",
        "scripts/load.py": "import pickle\nwith open(path, 'rb') as handle:\n    state = pickle.load(handle)\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert rules(findings)["AEGIS_UNSAFE_DESERIALIZATION"]["severity"] == "MEDIUM"


def test_yaml_safe_loader_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: safe-yaml\n---\n",
        "scripts/load.py": "import yaml\nconfig = yaml.load(text, Loader=yaml.SafeLoader)\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert findings == []


def test_test_fixture_is_excluded(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: controls-tests\n---\n",
        "tests/test_controls.py": "import os\nos.chmod('/tmp/example', 0o777)\n",
    })
    findings, _ = analyze_enterprise_controls(root)
    assert findings == []


def test_findings_are_deterministic_and_do_not_retain_raw_values(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: deterministic\n---\n",
        "scripts/setup.py": "import os\nos.chmod('/srv/private-name', 0o777)\n",
    })
    first, _ = analyze_enterprise_controls(root)
    second, _ = analyze_enterprise_controls(root)
    assert first == second
    assert "/srv/private-name" not in first[0]["evidence"]
    assert "raw_value_retained=false" in first[0]["evidence"]


def test_scan_skill_path_exposes_enterprise_analyzer(tmp_path: Path, monkeypatch) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: integrated-permission\n---\n",
        "scripts/setup.py": "import os\nos.chmod('/srv/data', 0o777)\n",
    })
    report = {"results": [{"skill_name": "integrated-permission", "analyzers_used": ["static_analyzer"], "findings": []}]}

    class FakeAdapter:
        def scan(self, _path: Path) -> AdapterResult:
            return AdapterResult(report=report, logs=["completed"])

    job = ScanJob(
        id="enterprise-controls-integration",
        created_at="2026-08-21T00:00:00+00:00",
        updated_at="2026-08-21T00:00:00+00:00",
        status="running",
        target_kind="skill",
        source_kind="upload",
        display_name="integrated-permission.zip",
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "SKILL_ADAPTER", FakeAdapter())
    monkeypatch.setattr(gateway, "save_job", lambda _job: None)
    gateway.scan_skill_path(job, root)
    assert job["status"] == "completed"
    assert job["decision"] == "REVIEW"
    assert ANALYZER_ID in job["analyzers"]
