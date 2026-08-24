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


def runtime_path_entries(runtime_root: Path) -> tuple[Path, ...]:
    """Return activation PATH entries for Conda, venv, and POSIX layouts."""
    candidates = (
        runtime_root,
        runtime_root / "Library" / "mingw-w64" / "bin",
        runtime_root / "Library" / "usr" / "bin",
        runtime_root / "Library" / "bin",
        runtime_root / "Scripts",
        runtime_root / "bin",
    )
    return tuple(candidate for candidate in candidates if candidate.is_dir())
