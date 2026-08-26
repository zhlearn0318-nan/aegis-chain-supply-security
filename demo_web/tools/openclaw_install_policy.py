#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[1]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.openclaw_install_policy import (  # noqa: E402
    block_response,
    evaluate_install_request,
)
from backend.install_policy_audit import record_install_policy_audit  # noqa: E402


MAX_STDIN_BYTES = 1024 * 1024


def main() -> int:
    # OpenClaw protocol v1 requires UTF-8 regardless of the Windows console code page.
    sys.stdout.reconfigure(encoding="utf-8", errors="strict", newline="")
    started = time.perf_counter()
    audited_by_evaluator = False
    audit_payload = None
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            response = block_response(
                "AEGIS_POLICY_INVALID_REQUEST",
                "OpenClaw install policy 请求超过 1 MiB 上限。",
            )
        else:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                response = block_response(
                    "AEGIS_POLICY_INVALID_REQUEST",
                    f"无法解析 OpenClaw install policy JSON：{type(exc).__name__}",
                )
            else:
                audit_payload = payload
                response = evaluate_install_request(
                    payload, audit_recorder=record_install_policy_audit
                )
                audited_by_evaluator = True
    except Exception as exc:
        response = block_response(
            "AEGIS_POLICY_INTERNAL_ERROR",
            f"安装前准入适配器发生内部错误：{type(exc).__name__}",
        )

    if not audited_by_evaluator:
        try:
            record_install_policy_audit(
                audit_payload,
                response,
                None,
                max(0, int((time.perf_counter() - started) * 1000)),
            )
        except Exception:
            response = block_response(
                "AEGIS_POLICY_AUDIT_FAILED",
                "安装前准入审计记录未能可靠持久化，已按失败关闭策略阻止安装。",
            )

    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
