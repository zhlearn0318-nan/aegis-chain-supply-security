from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .bootstrap import EVENT_PREFIX
from .markers import MarkerSpec, create_marker, encode_marker, find_marker_witnesses
from .policy import canonical_argv_sha256, command_line_sha256, is_within


DYNAMIC_AUDIT_SCHEMA_VERSION = "1.0"
MAX_FIXTURES = 10
MAX_TIMEOUT_SECONDS = 5.0
MAX_INPUT_CHARS = 4096
FIXTURE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
BOOTSTRAP_PATH = Path(__file__).resolve().with_name("bootstrap.py")
DEMO_ROOT = Path(__file__).resolve().parents[2]
MARKER_FLOW_FIXTURE_PATH = DEMO_ROOT / "tools" / "dynamic" / "fixtures" / "marker_file_to_loopback.py"
MARKER_FLOW_FIXTURE_SHA256 = "706bcd68731b2e4844cedd6e04095fd1a48ea26d3832df14a1f2463bd9f968a0"

EVENT_RULE_IDS = {
    "process_spawn": "AEGIS_DYNAMIC_SUBPROCESS_OBSERVED",
    "stdin_read": "AEGIS_DYNAMIC_STDIN_READ_OBSERVED",
    "environment_read": "AEGIS_DYNAMIC_ENVIRONMENT_READ_OBSERVED",
    "file_read": "AEGIS_DYNAMIC_FILE_READ_OBSERVED",
    "file_write": "AEGIS_DYNAMIC_FILE_WRITE_OBSERVED",
    "file_mutation": "AEGIS_DYNAMIC_FILE_MUTATION_OBSERVED",
    "directory_change": "AEGIS_DYNAMIC_DIRECTORY_CHANGE_OBSERVED",
    "network_connect": "AEGIS_DYNAMIC_LOOPBACK_CONNECT_OBSERVED",
}


class DynamicAuditConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class FixtureSpec:
    fixture_id: str
    script: Path
    sha256: str
    timeout_seconds: float
    stdin_payload: str
    environment: dict[str, str]
    allow_loopback: bool
    loopback_payload: str
    allowed_child_argv_tails: tuple[tuple[str, ...], ...]
    expected_events: dict[str, int]


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DynamicAuditConfigurationError(f"{label} must be an object")
    return value


def _load_specs(config_path: Path) -> tuple[dict[str, Any], Path, list[FixtureSpec]]:
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DynamicAuditConfigurationError(f"Unable to read fixture config: {exc}") from exc
    payload = _require_mapping(payload, "config")
    if payload.get("schema_version") != DYNAMIC_AUDIT_SCHEMA_VERSION:
        raise DynamicAuditConfigurationError("Unsupported dynamic audit schema_version")
    if payload.get("fixture_set_id") != "aegis-safe-dynamic-fixtures-v1":
        raise DynamicAuditConfigurationError("Unexpected fixture_set_id")
    if payload.get("execution_trust") != "self_built_hash_locked_only":
        raise DynamicAuditConfigurationError("execution_trust must remain self_built_hash_locked_only")

    fixture_root_value = payload.get("fixture_root")
    if not isinstance(fixture_root_value, str):
        raise DynamicAuditConfigurationError("fixture_root must be a relative string")
    fixture_root = (DEMO_ROOT / fixture_root_value).resolve(strict=True)
    approved_root = (DEMO_ROOT / "tools" / "dynamic" / "fixtures").resolve(strict=True)
    if fixture_root != approved_root:
        raise DynamicAuditConfigurationError("fixture_root must be tools/dynamic/fixtures")

    rows = payload.get("fixtures")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FIXTURES:
        raise DynamicAuditConfigurationError(f"fixtures must contain 1-{MAX_FIXTURES} rows")

    seen_ids: set[str] = set()
    specs: list[FixtureSpec] = []
    for index, raw in enumerate(rows):
        row = _require_mapping(raw, f"fixtures[{index}]")
        fixture_id = row.get("id")
        if not isinstance(fixture_id, str) or not FIXTURE_ID_PATTERN.fullmatch(fixture_id):
            raise DynamicAuditConfigurationError(f"Invalid fixture id at index {index}")
        if fixture_id in seen_ids:
            raise DynamicAuditConfigurationError(f"Duplicate fixture id: {fixture_id}")
        seen_ids.add(fixture_id)

        script_value = row.get("script")
        if not isinstance(script_value, str):
            raise DynamicAuditConfigurationError(f"{fixture_id}: script must be a string")
        script_candidate = fixture_root / script_value
        if script_candidate.is_symlink():
            raise DynamicAuditConfigurationError(f"{fixture_id}: symbolic-link fixture denied")
        script = script_candidate.resolve(strict=True)
        if not is_within(script, fixture_root):
            raise DynamicAuditConfigurationError(f"{fixture_id}: fixture path escapes approved root")

        digest = row.get("sha256")
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise DynamicAuditConfigurationError(f"{fixture_id}: invalid sha256")
        if sha256_file(script) != digest:
            raise DynamicAuditConfigurationError(f"{fixture_id}: fixture sha256 mismatch")

        timeout = row.get("timeout_seconds")
        if not isinstance(timeout, (int, float)) or not 0.1 <= float(timeout) <= MAX_TIMEOUT_SECONDS:
            raise DynamicAuditConfigurationError(f"{fixture_id}: timeout must be 0.1-{MAX_TIMEOUT_SECONDS}")

        stdin_payload = row.get("stdin_payload", "")
        if not isinstance(stdin_payload, str) or len(stdin_payload) > MAX_INPUT_CHARS:
            raise DynamicAuditConfigurationError(f"{fixture_id}: invalid stdin_payload")

        environment_raw = _require_mapping(row.get("environment", {}), f"{fixture_id}.environment")
        environment: dict[str, str] = {}
        for key, value in environment_raw.items():
            if (
                not isinstance(key, str)
                or not key.startswith("AEGIS_")
                or not isinstance(value, str)
                or len(value) > MAX_INPUT_CHARS
            ):
                raise DynamicAuditConfigurationError(f"{fixture_id}: invalid environment entry")
            environment[key] = value

        allow_loopback = row.get("allow_loopback", False)
        if not isinstance(allow_loopback, bool):
            raise DynamicAuditConfigurationError(f"{fixture_id}: allow_loopback must be boolean")
        loopback_payload = row.get("loopback_payload", "")
        if not isinstance(loopback_payload, str) or len(loopback_payload) > MAX_INPUT_CHARS:
            raise DynamicAuditConfigurationError(f"{fixture_id}: invalid loopback_payload")
        if allow_loopback and not loopback_payload:
            raise DynamicAuditConfigurationError(f"{fixture_id}: loopback payload is required")
        if not allow_loopback and loopback_payload:
            raise DynamicAuditConfigurationError(f"{fixture_id}: loopback payload requires allow_loopback")

        tails_raw = row.get("allowed_child_argv_tails", [])
        if not isinstance(tails_raw, list):
            raise DynamicAuditConfigurationError(f"{fixture_id}: invalid allowed_child_argv_tails")
        tails: list[tuple[str, ...]] = []
        for tail in tails_raw:
            if (
                not isinstance(tail, list)
                or not tail
                or any(not isinstance(item, str) or len(item) > MAX_INPUT_CHARS for item in tail)
            ):
                raise DynamicAuditConfigurationError(f"{fixture_id}: invalid child argv tail")
            tails.append(tuple(tail))

        expected_raw = _require_mapping(row.get("expected_events"), f"{fixture_id}.expected_events")
        expected: dict[str, int] = {}
        for event_type, minimum in expected_raw.items():
            if event_type not in EVENT_RULE_IDS or not isinstance(minimum, int) or minimum < 1:
                raise DynamicAuditConfigurationError(f"{fixture_id}: invalid expected event")
            expected[event_type] = minimum

        specs.append(FixtureSpec(
            fixture_id=fixture_id,
            script=script,
            sha256=digest,
            timeout_seconds=float(timeout),
            stdin_payload=stdin_payload,
            environment=environment,
            allow_loopback=allow_loopback,
            loopback_payload=loopback_payload,
            allowed_child_argv_tails=tuple(tails),
            expected_events=expected,
        ))
    return payload, fixture_root, specs


class _LoopbackServer:
    def __init__(
        self,
        expected_payload: str,
        markers: tuple[MarkerSpec, ...] = (),
    ) -> None:
        self.expected_payload = expected_payload.encode("utf-8")
        self.markers = markers
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.socket.settimeout(4.0)
        self.port = int(self.socket.getsockname()[1])
        self.result: dict[str, Any] = {
            "received": False,
            "payload_length": 0,
            "payload_sha256": None,
            "payload_matched": False,
            "error_type": None,
            "marker_witnesses": [],
        }
        self.thread = threading.Thread(target=self._serve, name="aegis-loopback-fixture", daemon=True)

    def _serve(self) -> None:
        try:
            connection, address = self.socket.accept()
            with connection:
                connection.settimeout(2.0)
                payload = connection.recv(MAX_INPUT_CHARS + 1)
                self.result.update({
                    "received": True,
                    "payload_length": len(payload),
                    "payload_sha256": sha256_bytes(payload),
                    "payload_matched": payload == self.expected_payload,
                    "peer_is_loopback": address[0] == "127.0.0.1",
                    "marker_witnesses": [
                        witness.to_dict()
                        for witness in find_marker_witnesses(
                            [payload],
                            self.markers,
                            sink_kind="loopback_network",
                            sink_ref="127.0.0.1:ephemeral",
                        )
                    ] if self.markers else [],
                })
                connection.sendall(b"OK")
        except BaseException as exc:
            self.result["error_type"] = type(exc).__name__
        finally:
            self.socket.close()

    def start(self) -> None:
        self.thread.start()

    def finish(self) -> dict[str, Any]:
        self.thread.join(timeout=5.0)
        if self.thread.is_alive():
            self.result["error_type"] = "ServerThreadTimeout"
            self.socket.close()
        return dict(self.result)


def _safe_environment(workspace: Path, fixture: FixtureSpec, port: int | None) -> dict[str, str]:
    temp_dir = workspace / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    environment = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "TEMP": str(temp_dir),
        "TMP": str(temp_dir),
        "AEGIS_FIXTURE_ID": fixture.fixture_id,
    }
    for key in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment.update(fixture.environment)
    if port is not None:
        environment["AEGIS_LOOPBACK_PORT"] = str(port)
        environment["AEGIS_LOOPBACK_PAYLOAD"] = fixture.loopback_payload
    return environment


def _parse_events(stderr: str, fixture_id: str) -> tuple[list[dict[str, Any]], str, int]:
    events: list[dict[str, Any]] = []
    non_event_lines: list[str] = []
    parse_errors = 0
    for line in stderr.splitlines():
        if not line.startswith(EVENT_PREFIX):
            non_event_lines.append(line)
            continue
        try:
            raw = json.loads(line[len(EVENT_PREFIX):])
            event_type = str(raw["event_type"])
            details = raw.get("details", {})
            if not isinstance(details, dict):
                raise ValueError("details must be an object")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            parse_errors += 1
            continue
        if event_type not in EVENT_RULE_IDS and event_type not in {
            "fixture_completed",
            "fixture_exception",
            "policy_violation",
        }:
            parse_errors += 1
            continue
        event: dict[str, Any] = {
            "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
            "fixture_id": fixture_id,
            "sequence": len(events) + 1,
            "event_type": event_type,
            "details": details,
        }
        rule_id = EVENT_RULE_IDS.get(event_type)
        if rule_id:
            event.update({"rule_id": rule_id, "severity": "INFO", "policy_effect": "none"})
        events.append(event)
    return events, "\n".join(non_event_lines), parse_errors


def _workspace_files(workspace: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            raise DynamicAuditConfigurationError("Fixture created a symbolic link")
        if path.is_file():
            files.append({
                "path": path.relative_to(workspace).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            })
    return files


def _creation_flags() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _run_fixture(
    fixture: FixtureSpec,
    fixture_root: Path,
    workspace: Path,
    *,
    markers: tuple[MarkerSpec, ...] = (),
    preloaded_files: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    workspace.mkdir(parents=True, exist_ok=False)
    for relative_path, content in sorted((preloaded_files or {}).items()):
        candidate = Path(relative_path)
        target = (workspace / candidate).resolve(strict=False)
        if candidate.is_absolute() or not is_within(target, workspace):
            raise DynamicAuditConfigurationError("Preloaded file path escapes workspace")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    server = (
        _LoopbackServer(fixture.loopback_payload, markers)
        if fixture.allow_loopback
        else None
    )
    if server:
        server.start()

    allowed_hashes: list[str] = []
    for tail in fixture.allowed_child_argv_tails:
        allowed_hashes.extend([
            canonical_argv_sha256(["<PYTHON>", *tail]),
            command_line_sha256(subprocess.list2cmdline([sys.executable, *tail])),
        ])
    command = [
        sys.executable,
        "-I",
        str(BOOTSTRAP_PATH),
        "--fixture",
        str(fixture.script),
        "--fixture-root",
        str(fixture_root),
        "--fixture-sha256",
        fixture.sha256,
        "--workspace",
        str(workspace),
        "--allowed-loopback-port",
        str(server.port if server else 0),
    ]
    for digest in allowed_hashes:
        command.extend(["--allowed-process-argv-sha256", digest])

    started = time.perf_counter()
    timed_out = False
    return_code: int | None = None
    stdout = ""
    stderr = ""
    try:
        completed = subprocess.run(
            command,
            input=fixture.stdin_payload,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            cwd=workspace,
            env=_safe_environment(workspace, fixture, server.port if server else None),
            timeout=fixture.timeout_seconds,
            shell=False,
            creationflags=_creation_flags(),
            check=False,
        )
        return_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    events, non_event_stderr, parse_errors = _parse_events(stderr, fixture.fixture_id)
    event_counts = Counter(event["event_type"] for event in events)
    expected_checks = {
        event_type: {
            "minimum": minimum,
            "observed": event_counts[event_type],
            "passed": event_counts[event_type] >= minimum,
        }
        for event_type, minimum in sorted(fixture.expected_events.items())
    }
    policy_violations = event_counts["policy_violation"]
    server_result = server.finish() if server else None
    server_ok = (
        server_result is None
        or (
            server_result.get("received") is True
            and server_result.get("payload_matched") is True
            and server_result.get("peer_is_loopback") is True
            and server_result.get("error_type") is None
        )
    )
    completed_ok = (
        not timed_out
        and return_code == 0
        and parse_errors == 0
        and policy_violations == 0
        and all(check["passed"] for check in expected_checks.values())
        and server_ok
    )
    result = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "fixture_id": fixture.fixture_id,
        "status": "completed" if completed_ok else "failed",
        "fixture_sha256": fixture.sha256,
        "duration_ms": elapsed_ms,
        "timeout_seconds": fixture.timeout_seconds,
        "timed_out": timed_out,
        "return_code": return_code,
        "event_counts": dict(sorted(event_counts.items())),
        "expected_event_checks": expected_checks,
        "policy_violations": policy_violations,
        "event_parse_errors": parse_errors,
        "stdout": {"bytes": len(stdout.encode("utf-8")), "sha256": sha256_bytes(stdout.encode("utf-8"))},
        "stderr_non_event": {
            "bytes": len(non_event_stderr.encode("utf-8")),
            "sha256": sha256_bytes(non_event_stderr.encode("utf-8")),
        },
        "loopback_server": server_result,
        "workspace_files": _workspace_files(workspace),
        "raw_output_retained": False,
        "policy_effect": "none",
    }
    return result, events


def run_safe_fixture_set(config_path: Path, workspace_root: Path) -> dict[str, Any]:
    config_path = config_path.resolve(strict=True)
    _, fixture_root, specs = _load_specs(config_path)
    workspace_root = workspace_root.resolve(strict=False)
    workspace_root.mkdir(parents=True, exist_ok=False)

    results: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for fixture in specs:
        result, fixture_events = _run_fixture(
            fixture,
            fixture_root,
            workspace_root / fixture.fixture_id,
        )
        results.append(result)
        events.extend(fixture_events)

    expected_total = sum(len(item["expected_event_checks"]) for item in results)
    expected_passed = sum(
        1
        for item in results
        for check in item["expected_event_checks"].values()
        if check["passed"]
    )
    evidence_events = [event for event in events if event.get("severity") == "INFO"]
    serialized_evidence = json.dumps(
        {"results": results, "events": evidence_events},
        ensure_ascii=False,
        sort_keys=True,
    )
    raw_values = [
        value
        for spec in specs
        for value in [
            spec.stdin_payload,
            *spec.environment.values(),
            spec.loopback_payload,
        ]
        if value
    ]
    raw_token_leaks = sum(serialized_evidence.count(value) for value in raw_values)
    aggregate_event_counts = Counter(event["event_type"] for event in evidence_events)
    metrics = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "fixture_set_id": "aegis-safe-dynamic-fixtures-v1",
        "fixtures_total": len(results),
        "fixtures_completed": sum(item["status"] == "completed" for item in results),
        "fixtures_failed": sum(item["status"] != "completed" for item in results),
        "expected_checks_total": expected_total,
        "expected_checks_passed": expected_passed,
        "policy_violations": sum(item["policy_violations"] for item in results),
        "timeouts": sum(item["timed_out"] for item in results),
        "event_parse_errors": sum(item["event_parse_errors"] for item in results),
        "event_type_counts": dict(sorted(aggregate_event_counts.items())),
        "server_receipts": sum(
            bool(item["loopback_server"] and item["loopback_server"].get("received"))
            for item in results
        ),
        "server_payload_matches": sum(
            bool(item["loopback_server"] and item["loopback_server"].get("payload_matched"))
            for item in results
        ),
        "non_info_evidence": sum(
            event.get("severity") not in {None, "INFO"} for event in events
        ),
        "raw_token_leaks": raw_token_leaks,
        "protected_samples_read": 0,
        "protected_samples_executed": 0,
        "internet_connections_allowed": 0,
        "decision_changes": 0,
        "duration_ms": {
            "total": sum(item["duration_ms"] for item in results),
            "mean": (
                sum(item["duration_ms"] for item in results) / len(results)
                if results
                else 0.0
            ),
            "max": max((item["duration_ms"] for item in results), default=0),
        },
    }
    success = (
        metrics["fixtures_completed"] == metrics["fixtures_total"]
        and metrics["expected_checks_passed"] == metrics["expected_checks_total"]
        and metrics["policy_violations"] == 0
        and metrics["timeouts"] == 0
        and metrics["event_parse_errors"] == 0
        and metrics["non_info_evidence"] == 0
        and metrics["raw_token_leaks"] == 0
        and metrics["protected_samples_read"] == 0
        and metrics["protected_samples_executed"] == 0
        and metrics["internet_connections_allowed"] == 0
        and metrics["decision_changes"] == 0
    )
    return {
        "success": success,
        "fixture_results": results,
        "events": events,
        "metrics": metrics,
        "fixture_paths": [str(spec.script) for spec in specs],
        "config_sha256": sha256_file(config_path),
    }


def run_safe_marker_flow_fixture(
    workspace_root: Path,
    *,
    seed: str = "aegis-dynamic-marker-flow-v1",
) -> dict[str, Any]:
    """Run one controlled source-to-sink marker fixture.

    This function never accepts a user-provided script, command, marker token, source
    path, or network destination.  It is a mechanism validation surface, not an
    untrusted-code sandbox.
    """
    fixture_root = (DEMO_ROOT / "tools" / "dynamic" / "fixtures").resolve(strict=True)
    fixture_path = MARKER_FLOW_FIXTURE_PATH.resolve(strict=True)
    if not is_within(fixture_path, fixture_root):
        raise DynamicAuditConfigurationError("Marker fixture path escapes approved root")
    if sha256_file(fixture_path) != MARKER_FLOW_FIXTURE_SHA256:
        raise DynamicAuditConfigurationError("Marker fixture sha256 mismatch")

    source_ref = "decoys/official_document.txt"
    marker = create_marker(
        "official_document",
        seed=seed,
        source_ref=source_ref,
    )
    encoded_payload = encode_marker(marker, "base64").decode("ascii")
    fixture = FixtureSpec(
        fixture_id="marker_file_to_loopback",
        script=fixture_path,
        sha256=MARKER_FLOW_FIXTURE_SHA256,
        timeout_seconds=5.0,
        stdin_payload="",
        environment={},
        allow_loopback=True,
        loopback_payload=encoded_payload,
        allowed_child_argv_tails=(),
        expected_events={
            "environment_read": 1,
            "file_read": 1,
            "network_connect": 1,
        },
    )
    workspace_root = workspace_root.resolve(strict=False)
    workspace_root.mkdir(parents=True, exist_ok=False)
    fixture_result, events = _run_fixture(
        fixture,
        fixture_root,
        workspace_root / fixture.fixture_id,
        markers=(marker,),
        preloaded_files={source_ref: marker.token},
    )
    loopback = fixture_result.get("loopback_server") or {}
    witnesses = list(loopback.get("marker_witnesses") or [])
    public_marker = marker.public_identity()
    serialized_public_result = json.dumps(
        {
            "fixture_result": fixture_result,
            "events": events,
            "marker": public_marker,
            "witnesses": witnesses,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    raw_marker_leaks = serialized_public_result.count(marker.token)
    evidence_events = [event for event in events if event.get("severity") == "INFO"]
    metrics = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "fixture_set_id": "aegis-safe-marker-flow-v1",
        "fixtures_total": 1,
        "fixtures_completed": int(fixture_result["status"] == "completed"),
        "expected_checks_total": len(fixture_result["expected_event_checks"]),
        "expected_checks_passed": sum(
            int(check["passed"])
            for check in fixture_result["expected_event_checks"].values()
        ),
        "marker_profiles_total": 1,
        "marker_witnesses": len(witnesses),
        "source_to_sink_witness_rate": float(bool(witnesses)),
        "confirmed_transforms": sorted({
            str(witness.get("transform")) for witness in witnesses
        }),
        "event_type_counts": dict(sorted(Counter(
            event["event_type"] for event in evidence_events
        ).items())),
        "policy_violations": fixture_result["policy_violations"],
        "timeouts": int(fixture_result["timed_out"]),
        "event_parse_errors": fixture_result["event_parse_errors"],
        "raw_marker_leaks": raw_marker_leaks,
        "protected_samples_read": 0,
        "protected_samples_executed": 0,
        "internet_connections_allowed": 0,
        "decision_changes": 0,
        "duration_ms": fixture_result["duration_ms"],
    }
    success = (
        fixture_result["status"] == "completed"
        and metrics["expected_checks_passed"] == metrics["expected_checks_total"]
        and metrics["marker_witnesses"] == 1
        and metrics["confirmed_transforms"] == ["base64"]
        and metrics["policy_violations"] == 0
        and metrics["timeouts"] == 0
        and metrics["event_parse_errors"] == 0
        and metrics["raw_marker_leaks"] == 0
        and metrics["decision_changes"] == 0
    )
    return {
        "success": success,
        "fixture_result": fixture_result,
        "events": events,
        "marker": public_marker,
        "marker_witnesses": witnesses,
        "metrics": metrics,
        "fixture_sha256": MARKER_FLOW_FIXTURE_SHA256,
    }
