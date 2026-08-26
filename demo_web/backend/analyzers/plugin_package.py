from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-openclaw-plugin-package-v1"
MAX_JSON_BYTES = 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 15 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
NATIVE_MANIFEST = "openclaw.plugin.json"
COMPATIBLE_MANIFESTS = (
    "plugin.json",
    ".codex-plugin/plugin.json",
    ".claude-plugin/plugin.json",
    ".cursor-plugin/plugin.json",
)
RISKY_LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".wasm", ".node"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}
EXACT_VERSION = re.compile(r"^(?:\d+!)?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    file: str,
    evidence: str,
) -> dict[str, Any]:
    identity = hashlib.sha256(f"{rule_id}|{file}|{evidence}".encode()).hexdigest()[:12]
    return finding_dict(
        id=f"{rule_id}_{identity}",
        title=title,
        category="openclaw_plugin_supply_chain",
        severity=severity,
        analyzer=ANALYZER_ID,
        location={"file": file},
        evidence=f"{evidence}; raw_value_retained=false",
        description="The staged OpenClaw plugin package violates a bounded installation-safety contract.",
        remediation="Use a source-inspectable, pinned plugin package with contained entrypoints and least-privilege MCP definitions.",
        rule_id=rule_id,
    )


def _read_json(root: Path, relative: str) -> dict[str, Any]:
    path = root / Path(*PurePosixPath(relative).parts)
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"{relative} exceeds the JSON inspection limit")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{relative} must contain an object")
    return payload


def _contained_file(root: Path, value: Any) -> tuple[bool, bool, str]:
    if not isinstance(value, str) or not value.strip():
        return False, False, "invalid"
    # Rebuild with PurePosixPath so Windows backslashes cannot hide traversal.
    normalized = value.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not parts or any(part in {"", ".", ".."} for part in parts) or PurePosixPath(normalized).is_absolute():
        return False, False, normalized[:180]
    path = root.joinpath(*parts).resolve(strict=False)
    contained = path == root or root in path.parents
    return contained, path.is_file() if contained else False, normalized[:180]


def _contained_directory(root: Path, value: Any) -> tuple[bool, bool, str]:
    if not isinstance(value, str) or not value.strip():
        return False, False, "invalid"
    normalized = value.replace("\\", "/").rstrip("/")
    if normalized in {"", "."}:
        return True, True, "."
    parts = PurePosixPath(normalized).parts
    if not parts or any(part in {"", ".", ".."} for part in parts) or PurePosixPath(normalized).is_absolute():
        return False, False, normalized[:180]
    path = root.joinpath(*parts).resolve(strict=False)
    contained = path == root or root in path.parents
    return contained, path.is_dir() if contained else False, normalized[:180]


def _analyze_mcp_servers(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    servers = manifest.get("mcpServers")
    if servers is None:
        return findings
    if not isinstance(servers, dict):
        return [_finding("AEGIS_PLUGIN_MCP_SERVERS_INVALID", "HIGH", "Plugin MCP server definitions are invalid", NATIVE_MANIFEST, "mcp_servers_not_object")]
    for server_name, server in sorted(servers.items()):
        label = str(server_name)[:80]
        if not isinstance(server, dict):
            findings.append(_finding("AEGIS_PLUGIN_MCP_SERVER_INVALID", "HIGH", "Plugin MCP server definition is invalid", NATIVE_MANIFEST, f"server={label}; reason=not_object"))
            continue
        transport = str(server.get("transport") or "stdio").lower()
        if transport == "stdio":
            command = str(server.get("command") or "").strip()
            lowered = Path(command).name.lower()
            if Path(command).is_absolute():
                findings.append(_finding("AEGIS_PLUGIN_MCP_ABSOLUTE_COMMAND", "HIGH", "Plugin MCP server binds to an absolute host command", NATIVE_MANIFEST, f"server={label}; command_class=absolute"))
            if lowered in {"npx", "npx.cmd", "uvx", "pipx"}:
                findings.append(_finding("AEGIS_PLUGIN_MCP_RUNTIME_PACKAGE_FETCH", "HIGH", "Plugin MCP server fetches code at runtime", NATIVE_MANIFEST, f"server={label}; launcher={lowered}"))
            if lowered in {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}:
                findings.append(_finding("AEGIS_PLUGIN_MCP_SHELL_LAUNCH", "HIGH", "Plugin MCP server launches through a shell", NATIVE_MANIFEST, f"server={label}; launcher={lowered}"))
            for argument in server.get("args") or []:
                if argument in {"-c", "-e", "--eval", "--require", "--loader"}:
                    findings.append(_finding("AEGIS_PLUGIN_MCP_INTERPRETER_FLAG", "HIGH", "Plugin MCP server uses an interpreter code-loading flag", NATIVE_MANIFEST, f"server={label}; flag={argument}"))
                if isinstance(argument, str) and argument.startswith(("./", ".\\")):
                    contained, exists, normalized = _contained_file(root, argument)
                    if not contained or not exists:
                        findings.append(_finding("AEGIS_PLUGIN_MCP_ENTRY_INVALID", "HIGH", "Plugin MCP server entry is missing or escapes the package", NATIVE_MANIFEST, f"server={label}; entry={normalized}"))
            for field in ("cwd", "workingDirectory"):
                if field in server:
                    contained, exists, _ = _contained_directory(root, server[field])
                    if not contained or not exists:
                        findings.append(_finding("AEGIS_PLUGIN_MCP_WORKDIR_INVALID", "HIGH", "Plugin MCP working directory is missing or escapes the package", NATIVE_MANIFEST, f"server={label}; field={field}"))
        elif transport in {"http", "sse", "streamable-http"}:
            url = str(server.get("url") or "")
            if not url.startswith("https://"):
                findings.append(_finding("AEGIS_PLUGIN_MCP_INSECURE_REMOTE", "HIGH", "Plugin MCP server uses a non-HTTPS or missing endpoint", NATIVE_MANIFEST, f"server={label}; transport={transport}"))
            if server.get("verifyTls") is False or server.get("tlsVerify") is False:
                findings.append(_finding("AEGIS_PLUGIN_MCP_TLS_DISABLED", "HIGH", "Plugin MCP server disables TLS verification", NATIVE_MANIFEST, f"server={label}; tls_verification=false"))
            headers = server.get("headers")
            if isinstance(headers, dict):
                for name, value in headers.items():
                    if str(name).lower() in {"authorization", "proxy-authorization", "x-api-key"} and isinstance(value, str) and value and not value.startswith(("${", "{{")):
                        findings.append(_finding("AEGIS_PLUGIN_MCP_EMBEDDED_SECRET", "HIGH", "Plugin MCP definition embeds a credential-like value", NATIVE_MANIFEST, f"server={label}; header_name={str(name)[:80]}"))
        else:
            findings.append(_finding("AEGIS_PLUGIN_MCP_TRANSPORT_UNKNOWN", "MEDIUM", "Plugin MCP transport requires review", NATIVE_MANIFEST, f"server={label}; transport={transport[:40]}"))
        env = server.get("env")
        if isinstance(env, dict):
            for name, value in env.items():
                if re.search(r"(?i)(?:token|secret|password|api[_-]?key)", str(name)) and isinstance(value, str) and value and not value.startswith(("${", "{{")):
                    findings.append(_finding("AEGIS_PLUGIN_MCP_EMBEDDED_SECRET", "HIGH", "Plugin MCP definition embeds a credential-like value", NATIVE_MANIFEST, f"server={label}; env_name={str(name)[:80]}"))
    return findings


def analyze_plugin_package(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    root = root.resolve(strict=True)
    findings: list[dict[str, Any]] = []
    native_path = root / NATIVE_MANIFEST
    compatible = next((item for item in COMPATIBLE_MANIFESTS if (root / Path(*PurePosixPath(item).parts)).is_file()), None)
    manifest: dict[str, Any] | None = None
    if native_path.is_file():
        try:
            manifest = _read_json(root, NATIVE_MANIFEST)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            findings.append(_finding("AEGIS_PLUGIN_MANIFEST_INVALID", "HIGH", "OpenClaw plugin manifest cannot be validated", NATIVE_MANIFEST, "manifest_parse_or_shape_error"))
        if manifest is not None:
            if not isinstance(manifest.get("id"), str) or not manifest["id"].strip():
                findings.append(_finding("AEGIS_PLUGIN_ID_MISSING", "HIGH", "OpenClaw plugin id is missing", NATIVE_MANIFEST, "required_id_missing"))
            if not isinstance(manifest.get("configSchema"), dict):
                findings.append(_finding("AEGIS_PLUGIN_CONFIG_SCHEMA_MISSING", "HIGH", "OpenClaw plugin config schema is missing", NATIVE_MANIFEST, "required_config_schema_missing"))
            findings.extend(_analyze_mcp_servers(root, manifest))
    elif compatible:
        findings.append(_finding("AEGIS_PLUGIN_COMPATIBLE_BUNDLE_REVIEW", "MEDIUM", "Compatible plugin bundle requires format-specific review", compatible, f"manifest={compatible}"))
    else:
        findings.append(_finding("AEGIS_PLUGIN_MANIFEST_MISSING", "HIGH", "Plugin package has no supported manifest", "package-root", "supported_manifest_missing"))

    package_path = root / "package.json"
    if not package_path.is_file():
        findings.append(_finding("AEGIS_PLUGIN_PACKAGE_JSON_MISSING", "MEDIUM", "Plugin package.json is missing", "package-root", "package_json_missing"))
    else:
        try:
            package = _read_json(root, "package.json")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            findings.append(_finding("AEGIS_PLUGIN_PACKAGE_JSON_INVALID", "HIGH", "Plugin package.json cannot be validated", "package.json", "package_json_parse_or_shape_error"))
            package = {}
        scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
        for name in sorted(RISKY_LIFECYCLE_SCRIPTS & set(scripts)):
            findings.append(_finding("AEGIS_PLUGIN_LIFECYCLE_SCRIPT", "HIGH", "Plugin defines an install-time lifecycle script", "package.json", f"script={name}"))
        openclaw = package.get("openclaw") if isinstance(package.get("openclaw"), dict) else {}
        entries = openclaw.get("extensions") if isinstance(openclaw.get("extensions"), list) else []
        if native_path.is_file() and not entries:
            findings.append(_finding("AEGIS_PLUGIN_ENTRY_MISSING", "HIGH", "Native plugin has no declared entrypoint", "package.json", "openclaw_extensions_missing"))
        for entry in entries:
            contained, exists, normalized = _contained_file(root, entry)
            if not contained:
                findings.append(_finding("AEGIS_PLUGIN_ENTRY_ESCAPE", "CRITICAL", "Plugin entrypoint escapes the package", "package.json", f"entry={normalized}"))
            elif not exists:
                findings.append(_finding("AEGIS_PLUGIN_ENTRY_NOT_FOUND", "HIGH", "Plugin entrypoint does not exist", "package.json", f"entry={normalized}"))
        dependencies = package.get("dependencies") if isinstance(package.get("dependencies"), dict) else {}
        for name, specifier in sorted(dependencies.items()):
            value = str(specifier)
            if not EXACT_VERSION.fullmatch(value):
                findings.append(_finding("AEGIS_PLUGIN_DEPENDENCY_UNPINNED", "MEDIUM", "Plugin dependency is not pinned to an exact version", "package.json", f"dependency={str(name)[:100]}; specifier_class=non_exact"))
        if dependencies and not any((root / name).is_file() for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
            findings.append(_finding("AEGIS_PLUGIN_LOCKFILE_MISSING", "MEDIUM", "Plugin dependencies have no lockfile", "package.json", "dependency_lock_missing"))

    file_count = 0
    total_bytes = 0
    gap_count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().lower()):
        if not path.is_file():
            continue
        file_count += 1
        size = path.stat().st_size
        total_bytes += size
        relative = path.relative_to(root).as_posix()
        if file_count > MAX_FILES or size > MAX_FILE_BYTES or total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("Plugin package exceeds bounded inspection limits")
        if path.suffix.lower() in EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS:
            gap_count += 1
            findings.append(_finding("AEGIS_PLUGIN_UNINSPECTED_PAYLOAD", "MEDIUM", "Plugin contains a binary or nested package outside source inspection", relative, f"extension={path.suffix.lower()}"))
    findings.append(_finding("AEGIS_PLUGIN_COVERAGE_SUMMARY", "INFO", "Plugin package inspection coverage summary", NATIVE_MANIFEST if native_path.is_file() else "package-root", f"files_total={file_count}; bytes_total={total_bytes}; coverage_gaps={gap_count}"))
    return findings, [ANALYZER_ID]
