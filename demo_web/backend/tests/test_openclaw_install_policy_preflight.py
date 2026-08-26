from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_contract_only_preflight_is_diagnostic_and_not_deployment_ready(
    tmp_path: Path,
) -> None:
    script = Path(__file__).resolve().parents[2] / "tools" / "openclaw_install_policy_preflight.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--skip-fixed-scans"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=20,
    )
    payload = json.loads(completed.stdout)
    checks = {item["id"]: item for item in payload["checks"]}

    assert completed.returncode == 1
    assert payload["ready"] is False
    assert checks["required_files"]["passed"] is True
    assert checks["scanner_environment_allowlist"]["passed"] is True
    assert checks["scanner_environment_allowlist"]["detail"][
        "inherited_service_environment"
    ] is False
    assert checks["fixed_safe_and_risky_scans"]["passed"] is False
