from __future__ import annotations

from pathlib import Path

from backend.runtime_paths import resolve_runtime_python


def test_resolve_runtime_python_supports_conda_venv_and_posix(
    tmp_path: Path,
) -> None:
    conda = tmp_path / "conda"
    venv = tmp_path / "venv"
    posix = tmp_path / "posix"
    conda.mkdir()
    (venv / "Scripts").mkdir(parents=True)
    (posix / "bin").mkdir(parents=True)
    (conda / "python.exe").touch()
    (venv / "Scripts" / "python.exe").touch()
    (posix / "bin" / "python").touch()

    assert resolve_runtime_python(conda) == conda / "python.exe"
    assert resolve_runtime_python(venv) == venv / "Scripts" / "python.exe"
    assert resolve_runtime_python(posix) == posix / "bin" / "python"


def test_resolve_runtime_python_has_deterministic_missing_path(tmp_path: Path) -> None:
    runtime = tmp_path / "missing"
    assert resolve_runtime_python(runtime) == runtime / "python.exe"
