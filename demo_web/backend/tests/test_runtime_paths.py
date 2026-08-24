from __future__ import annotations

from pathlib import Path

from backend.runtime_paths import resolve_runtime_python, runtime_path_entries


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


def test_runtime_path_entries_include_conda_library_bin(tmp_path: Path) -> None:
    runtime = tmp_path / "conda"
    library_bin = runtime / "Library" / "bin"
    scripts = runtime / "Scripts"
    library_bin.mkdir(parents=True)
    scripts.mkdir()

    entries = runtime_path_entries(runtime)

    assert entries[0] == runtime
    assert library_bin in entries
    assert scripts in entries
