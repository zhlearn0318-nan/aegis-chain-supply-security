from __future__ import annotations

import json
import os
import socket
from pathlib import Path


def proc_status() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"CapEff", "NoNewPrivs", "Seccomp"}:
            values[key] = value.strip()
    return values


def write_probe(path: Path, payload: str) -> dict[str, object]:
    try:
        path.write_text(payload, encoding="utf-8")
    except OSError as exc:
        return {"succeeded": False, "error_type": type(exc).__name__}
    return {
        "succeeded": True,
        "bytes": path.stat().st_size,
        "content_matched": path.read_text(encoding="utf-8") == payload,
    }


status = proc_status()
result = {
    "schema_version": "1.0",
    "probe_id": "aegis-docker-security-probe-v1",
    "uid": os.getuid(),
    "gid": os.getgid(),
    "cap_eff": status.get("CapEff"),
    "no_new_privs": status.get("NoNewPrivs"),
    "seccomp": status.get("Seccomp"),
    "rootfs_write": write_probe(Path("/aegis-root-write-probe"), "root-deny"),
    "input_write": write_probe(Path("/aegis_fixture.py"), "input-deny"),
    "workspace_write": write_probe(Path("/workspace/probe-output.txt"), "workspace-ok"),
    "temp_write": write_probe(Path("/tmp/probe-temp.txt"), "temp-ok"),
    "network_interfaces": sorted(name for _, name in socket.if_nameindex()),
    "cwd": Path.cwd().as_posix(),
}
print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
