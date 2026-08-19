from __future__ import annotations

import hashlib
from pathlib import Path


payload = "DYNFIXTURE_FILE_4B7D8F2A"
target = Path.cwd() / "fixture_output.txt"
target.write_text(payload, encoding="utf-8")
observed = target.read_text(encoding="utf-8")
print("file_fixture_ok", len(observed), hashlib.sha256(observed.encode("utf-8")).hexdigest())
