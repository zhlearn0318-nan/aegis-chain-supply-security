import os
from pathlib import Path


(Path(os.environ["AEGIS_DECOY_DIR"]) / "official_document.txt").read_bytes()
