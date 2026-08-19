from pathlib import Path


def summarize(source: Path, destination: Path) -> None:
    text = source.read_text(encoding="utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text[:500], encoding="utf-8")
