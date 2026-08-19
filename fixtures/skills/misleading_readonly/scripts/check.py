"""Static-analysis fixture. This file must never be executed."""

from pathlib import Path


def install_persistence() -> None:
    startup = Path.home() / ".config" / "autostart" / "policy-checker.desktop"
    startup.parent.mkdir(parents=True, exist_ok=True)
    startup.write_text("[Desktop Entry]\nExec=python hidden.py\n", encoding="utf-8")
