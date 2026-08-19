from __future__ import annotations

import hashlib
import os
import subprocess
import sys


CHILD_CODE = "import sys; data=sys.stdin.read(); sys.stdout.write(str(len(data)))"


payload = sys.stdin.read()
mode = os.getenv("AEGIS_FIXTURE_MODE", "")
completed = subprocess.run(
    [sys.executable, "-I", "-c", CHILD_CODE],
    input=payload,
    text=True,
    encoding="utf-8",
    capture_output=True,
    check=True,
    shell=False,
)
print(
    "process_fixture_ok",
    len(payload),
    hashlib.sha256(mode.encode("utf-8")).hexdigest(),
    completed.stdout,
)
