from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .adapters import McpScannerAdapter, ProcessRunner
from .custom_rules import analyze_custom_rules
from .install_policy_audit import record_install_policy_audit
from .models import Decision
from .normalizers import finding_dict, normalize_mcp
from .analyzers.mcp_policy import analyze_mcp_objects
from .policy import evaluate_findings
from .runtime_paths import resolve_runtime_python, runtime_path_entries


ANALYZER_ID = "aegis-openclaw-mcp-config-v1"
ROOT = Path(__file__).resolve().parents[2]
DEMO_ROOT = Path(__file__).resolve().parents[1]
MCP_RUNTIME = ROOT / ".runtime_mcp313"
MCP_PYTHON = resolve_runtime_python(MCP_RUNTIME)
MCP_SCANNER = MCP_RUNTIME / "Scripts" / "mcp-scanner.exe"
MCP_WRAPPER = ROOT / "scripts" / "run_mcp_static.py"
SERVER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
SHELLS = {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "sh", "bash", "zsh"}
FETCHERS = {"npx", "npx.cmd", "uvx", "pipx"}
CODE_FLAGS = {"-c", "-e", "--eval", "--require", "--loader"}
BLOCKED_ENV = {
    "NODE_OPTIONS", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT", "BASHOPTS", "KSH_ENV",
}
RunCommand = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _finding(rule_id: str, severity: str, title: str, evidence: str) -> dict[str, Any]:
    identity = hashlib.sha256(f"{rule_id}|{evidence}".encode("utf-8")).hexdigest()[:16]
    return finding_dict(
        id=f"{rule_id}_{identity}",
        title=title,
        category="openclaw_mcp_configuration",
        severity=severity,
        analyzer=ANALYZER_ID,
        location={"object": "mcp.server"},
        evidence=f"{evidence}; raw_value_retained=false",
        description="The proposed OpenClaw MCP server definition violates the pre-configuration admission contract.",
        remediation="Use a pinned local executable or a verified HTTPS endpoint, externalize credentials, and apply least-privilege tool filters.",
        rule_id=rule_id,
    )


def _literal_secret(name: Any, value: Any) -> bool:
    key = str(name).lower()
    return (
        bool(re.search(r"token|secret|password|api[_-]?key|authorization", key))
        and isinstance(value, str)
        and bool(value.strip())
        and not value.strip().startswith(("${", "{{"))
    )


def analyze_mcp_server_definition(name: str, server: Any) -> tuple[list[dict[str, Any]], list[str]]:
    if not SERVER_NAME.fullmatch(name):
        return [_finding("AEGIS_MCP_SERVER_NAME_INVALID", "HIGH", "MCP server name is invalid", "name_shape=invalid")], [ANALYZER_ID]
    if not isinstance(server, dict):
        return [_finding("AEGIS_MCP_SERVER_CONFIG_INVALID", "HIGH", "MCP server definition is invalid", "config_shape=not_object")], [ANALYZER_ID]
    findings: list[dict[str, Any]] = []
    command = str(server.get("command") or "").strip()
    url = str(server.get("url") or "").strip()
    transport = str(server.get("transport") or ("stdio" if command else "streamable-http" if url else "")).lower()
    if command and url:
        findings.append(_finding("AEGIS_MCP_TRANSPORT_AMBIGUOUS", "HIGH", "MCP definition mixes stdio and remote transport", "command_and_url=true"))
    elif command:
        launcher = Path(command).name.lower()
        if launcher in SHELLS:
            findings.append(_finding("AEGIS_MCP_SHELL_LAUNCH", "HIGH", "MCP server launches through a shell", f"launcher={launcher}"))
        if launcher in FETCHERS:
            findings.append(_finding("AEGIS_MCP_RUNTIME_PACKAGE_FETCH", "HIGH", "MCP server downloads or resolves code at runtime", f"launcher={launcher}"))
        for argument in server.get("args") or []:
            if str(argument) in CODE_FLAGS:
                findings.append(_finding("AEGIS_MCP_INTERPRETER_CODE_FLAG", "HIGH", "MCP server uses an interpreter code-loading flag", f"flag={str(argument)[:40]}"))
        cwd = server.get("cwd", server.get("workingDirectory"))
        if cwd and (not Path(str(cwd)).is_absolute() or not Path(str(cwd)).is_dir()):
            findings.append(_finding("AEGIS_MCP_WORKDIR_INVALID", "HIGH", "MCP working directory is missing or not absolute", "cwd_valid=false"))
    elif url:
        parsed = urlparse(url)
        local = (parsed.hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}
        if parsed.username or parsed.password:
            findings.append(_finding("AEGIS_MCP_URL_EMBEDDED_SECRET", "HIGH", "MCP URL embeds credentials", "url_userinfo=true"))
        if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
            findings.append(_finding("AEGIS_MCP_INSECURE_REMOTE", "HIGH", "Remote MCP endpoint does not use HTTPS", f"scheme={parsed.scheme or 'missing'}"))
        if server.get("sslVerify") is False or server.get("verifyTls") is False or server.get("tlsVerify") is False:
            findings.append(_finding("AEGIS_MCP_TLS_DISABLED", "HIGH", "MCP definition disables TLS verification", "tls_verification=false"))
    else:
        findings.append(_finding("AEGIS_MCP_TRANSPORT_MISSING", "HIGH", "MCP definition has no command or URL", f"transport={transport or 'missing'}"))
    env = server.get("env") if isinstance(server.get("env"), dict) else {}
    headers = server.get("headers") if isinstance(server.get("headers"), dict) else {}
    for key, value in env.items():
        normalized = str(key).upper()
        if normalized in BLOCKED_ENV or normalized.startswith(("LD_", "DYLD_", "BASH_FUNC_")):
            findings.append(_finding("AEGIS_MCP_ENV_INJECTION", "CRITICAL", "MCP environment contains a runtime injection key", f"env_name={normalized[:80]}"))
        if _literal_secret(key, value):
            findings.append(_finding("AEGIS_MCP_EMBEDDED_SECRET", "HIGH", "MCP definition embeds a credential-like environment value", f"env_name={str(key)[:80]}"))
    for key, value in headers.items():
        if _literal_secret(key, value):
            findings.append(_finding("AEGIS_MCP_EMBEDDED_SECRET", "HIGH", "MCP definition embeds a credential-like header value", f"header_name={str(key)[:80]}"))
    tool_filter = server.get("toolFilter")
    if not isinstance(tool_filter, dict) or not (tool_filter.get("include") or tool_filter.get("exclude")):
        findings.append(_finding("AEGIS_MCP_TOOL_FILTER_ABSENT", "INFO", "MCP server has no explicit tool filter", "least_privilege_filter=false"))
    unique = {finding["id"]: finding for finding in findings}
    return list(unique.values()), [ANALYZER_ID]


def _openclaw_command() -> tuple[str, str]:
    node = os.getenv("AEGIS_OPENCLAW_NODE", "").strip()
    module = os.getenv("AEGIS_OPENCLAW_MJS", "").strip()
    if not node:
        program_files = Path(os.getenv("ProgramFiles", r"C:\Program Files"))
        node = str(program_files / "nodejs" / "node.exe")
    if not module:
        appdata = Path(os.getenv("APPDATA", ""))
        module = str(appdata / "npm" / "node_modules" / "openclaw" / "openclaw.mjs")
    if not Path(node).is_file() or not Path(module).is_file():
        raise RuntimeError("OpenClaw CLI runtime is unavailable")
    return node, module


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=30, check=False)


def _completed_json_object(completed: subprocess.CompletedProcess[str]) -> dict[str, Any] | None:
    if completed.returncode != 0:
        return None
    try:
        value = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _restore_mcp_server(
    node: str,
    module: str,
    name: str,
    previous: dict[str, Any] | None,
    run_command: RunCommand,
) -> bool:
    if previous is None:
        restored = run_command([node, module, "mcp", "unset", name])
    else:
        canonical = json.dumps(previous, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        restored = run_command([node, module, "mcp", "set", name, canonical])
    return restored.returncode == 0


def _offline_discovery_findings(discovery: dict[str, Any], root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    paths = []
    for key, filename in (("tools", "tools.json"), ("prompts", "prompts.json"), ("resources", "resources.json")):
        value = discovery.get(key, [])
        if not isinstance(value, list):
            raise ValueError(f"discovery.{key} must be an array")
        path = root / filename
        path.write_text(json.dumps({key: value}, ensure_ascii=False), encoding="utf-8")
        paths.append(path)
    runner = ProcessRunner(timeout_seconds=30, cache_root=DEMO_ROOT / "data" / "cache", extra_path=runtime_path_entries(MCP_RUNTIME))
    adapter = McpScannerAdapter(python=MCP_PYTHON, wrapper=MCP_WRAPPER, scanner=MCP_SCANNER, runner=runner)
    execution = adapter.scan(*paths)
    vendor, vendor_analyzers = normalize_mcp(execution.report)
    policy, policy_analyzers = analyze_mcp_objects(*paths)
    return vendor + policy, sorted(set(vendor_analyzers + policy_analyzers))


def admit_mcp_server(
    request: dict[str, Any], *, commit: bool = True, run_command: RunCommand = _default_runner
) -> dict[str, Any]:
    started = time.perf_counter()
    name = str(request.get("name") or "").strip()
    server = request.get("server")
    canonical = json.dumps(server, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if isinstance(server, dict) else "invalid"
    source_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    findings, analyzers = analyze_mcp_server_definition(name, server)
    saved = False
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-mcp-admission-") as temporary:
            root = Path(temporary)
            definition = root / "server.json"
            definition.write_text(json.dumps(server, ensure_ascii=False), encoding="utf-8")
            custom, custom_analyzers = analyze_custom_rules(definition, "mcp")
            findings.extend(custom)
            analyzers.extend(custom_analyzers)
            discovery = request.get("discovery")
            if discovery is not None:
                if not isinstance(discovery, dict):
                    raise ValueError("discovery must be an object")
                discovered, discovery_analyzers = _offline_discovery_findings(discovery, root)
                findings.extend(discovered)
                analyzers.extend(discovery_analyzers)
        evaluation = evaluate_findings(findings)
        decision = evaluation.decision
        reason = evaluation.trace.reason
        if decision == Decision.REVIEW:
            decision = Decision.BLOCK
            reason = f"当前 OpenClaw 稳定版按安全兼容模式阻断复核项；{reason}"
        if decision == Decision.ALLOW and commit:
            node, module = _openclaw_command()
            snapshot = run_command([node, module, "mcp", "show", name, "--json"])
            snapshot_text = f"{snapshot.stdout}\n{snapshot.stderr}"
            previous = _completed_json_object(snapshot)
            snapshot_missing = snapshot.returncode != 0 and "No MCP server named" in snapshot_text
            if snapshot.returncode == 0 and previous is None:
                decision = Decision.BLOCK
                reason = "MCP 原配置无法可靠解析，未执行更新并失败关闭。"
                findings.insert(0, _finding("AEGIS_MCP_CONFIG_SNAPSHOT_FAILED", "CRITICAL", "Existing OpenClaw MCP configuration snapshot failed", "snapshot=parse_failed"))
            elif snapshot.returncode != 0 and not snapshot_missing:
                decision = Decision.BLOCK
                reason = "MCP 原配置无法可靠读取，未执行更新并失败关闭。"
                findings.insert(0, _finding("AEGIS_MCP_CONFIG_SNAPSHOT_FAILED", "CRITICAL", "Existing OpenClaw MCP configuration snapshot failed", f"exit_code={snapshot.returncode}"))
            else:
                completed = run_command([node, module, "mcp", "set", name, canonical])
                if completed.returncode != 0:
                    rollback_ok = _restore_mcp_server(node, module, name, previous, run_command)
                    decision = Decision.BLOCK
                    reason = "MCP 配置未能原子提交到 OpenClaw，已恢复原配置并失败关闭。" if rollback_ok else "MCP 配置提交失败且原配置恢复失败，必须人工处置。"
                    findings.insert(0, _finding("AEGIS_MCP_CONFIG_COMMIT_FAILED", "CRITICAL", "OpenClaw MCP configuration commit failed", f"exit_code={completed.returncode}; rollback={'ok' if rollback_ok else 'failed'}"))
                else:
                    verified = run_command([node, module, "mcp", "show", name, "--json"])
                    verified_payload = _completed_json_object(verified)
                    if verified_payload != server:
                        rollback_ok = _restore_mcp_server(node, module, name, previous, run_command)
                        decision = Decision.BLOCK
                        reason = "MCP 配置提交后复核不一致，已恢复原配置并失败关闭。" if rollback_ok else "MCP 配置复核失败且原配置恢复失败，必须人工处置。"
                        findings.insert(0, _finding("AEGIS_MCP_CONFIG_VERIFY_FAILED", "CRITICAL", "OpenClaw MCP configuration verification failed", f"verify_match=false; rollback={'ok' if rollback_ok else 'failed'}"))
                    else:
                        saved = True
        response_decision = "allow" if decision == Decision.ALLOW else "block"
        prioritized = sorted(findings, key=lambda item: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(str(item.get("severity")), 5))[:3]
        response = {
            "protocolVersion": 1,
            "decision": response_decision,
            "reason": reason,
            "findings": [
                {
                    "ruleId": item.get("rule_id") or item.get("id"),
                    "message": item.get("title"),
                    "severity": "critical" if item.get("severity") in {"CRITICAL", "HIGH"} else "warn" if item.get("severity") in {"MEDIUM", "LOW"} else "info",
                }
                for item in prioritized
            ],
        }
    except Exception as exc:
        response = {
            "protocolVersion": 1,
            "decision": "block",
            "reason": f"MCP 准入扫描未能可靠完成：{type(exc).__name__}",
            "findings": [{"ruleId": "AEGIS_MCP_ADMISSION_FAILED", "message": "MCP admission failed closed", "severity": "critical"}],
        }
        saved = False
    duration_ms = max(0, int((time.perf_counter() - started) * 1000))
    audit_payload = {
        "protocolVersion": 1,
        "openclawVersion": "2026.7.1-2",
        "targetType": "mcp",
        "targetName": name,
    }
    record_install_policy_audit(audit_payload, response, source_hash, duration_ms)
    return {
        "accepted": response["decision"] == "allow" and (saved or not commit),
        "decision": response["decision"].upper(),
        "saved": saved,
        "target_name": name,
        "config_sha256": source_hash,
        "duration_ms": duration_ms,
        "reason": response["reason"],
        "finding_rule_ids": [item["ruleId"] for item in response.get("findings", [])],
        "analyzers": sorted(set(analyzers)),
        "offline_discovery_scanned": request.get("discovery") is not None,
    }
