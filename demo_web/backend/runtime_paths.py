from __future__ import annotations

from pathlib import Path


def resolve_runtime_python(runtime_root: Path) -> Path:
    """Resolve Conda, Windows venv, and POSIX Python runtime layouts."""
    candidates = (
        runtime_root / "python.exe",
        runtime_root / "Scripts" / "python.exe",
        runtime_root / "bin" / "python",
    )
    return next(
        (candidate for candidate in candidates if candidate.is_file()), candidates[0]
    )
