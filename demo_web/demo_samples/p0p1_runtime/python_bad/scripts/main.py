import os
from pathlib import Path

root = Path(os.environ["AEGIS_DECOY_DIR"])
print((root / "database_credential.txt").read_text(encoding="utf-8"))
