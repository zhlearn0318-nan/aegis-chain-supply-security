#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[1]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.uploaded_skill_admission import (  # noqa: E402
    UploadedSkillError,
    prepare_uploaded_skill,
    scan_prepared_skill,
    verify_prepared_skill,
)


MAX_STDIN_BYTES = 128 * 1024


def _required_path(request: dict, key: str) -> Path:
    value = request.get(key)
    if not isinstance(value, str) or not value:
        raise UploadedSkillError("REQUEST_INVALID", f"缺少 {key}。")
    return Path(value)


def execute(request: dict) -> dict:
    operation = request.get("operation")
    if operation == "prepare_scan":
        print("[STEP 1/5] 验证上传会话与文件边界。", file=sys.stderr, flush=True)
        prepared = prepare_uploaded_skill(
            _required_path(request, "session_root"),
            _required_path(request, "uploads_root"),
            str(request.get("source_kind") or ""),
        )
        print(
            f"[STEP 2/5] 上传包预处理完成：files={prepared.file_count} bytes={prepared.total_bytes}。",
            file=sys.stderr,
            flush=True,
        )
        print(f"[hash] source_tree_sha256={prepared.source_tree_sha256}", file=sys.stderr, flush=True)
        print("[STEP 3/5] 执行 Cisco Skill Scanner 与 Aegis 静态规则。", file=sys.stderr, flush=True)
        print("[STEP 4/5] 静态准入后执行 Docker 隔离试运行。", file=sys.stderr, flush=True)
        result = scan_prepared_skill(prepared, str(request.get("target_name") or ""))
        print(
            f"[STEP 5/5] 扫描完成：decision={result['decision']} chain_valid={result['audit_integrity'].get('valid')}。",
            file=sys.stderr,
            flush=True,
        )
        return result
    if operation == "verify":
        return verify_prepared_skill(
            _required_path(request, "source_root"),
            str(request.get("expected_sha256") or ""),
        )
    raise UploadedSkillError("OPERATION_INVALID", "不支持的上传 Skill 操作。")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="strict", newline="")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            raise UploadedSkillError("REQUEST_TOO_LARGE", "请求超过 128 KiB。")
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise UploadedSkillError("REQUEST_INVALID", "请求必须是 JSON 对象。")
        data = execute(request)
        response = {"ok": True, "data": data}
    except UploadedSkillError as exc:
        response = {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
    except (UnicodeDecodeError, json.JSONDecodeError):
        response = {"ok": False, "error": {"code": "REQUEST_INVALID", "message": "请求 JSON 无效。"}}
    except Exception as exc:
        response = {
            "ok": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": f"上传 Skill 处理失败：{type(exc).__name__}",
            },
        }
    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
