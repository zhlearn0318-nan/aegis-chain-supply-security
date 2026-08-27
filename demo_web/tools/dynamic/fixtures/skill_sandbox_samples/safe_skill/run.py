from pathlib import Path


Path("/workspace/safe-result.txt").write_text(
    "aegis controlled benign fixture\n",
    encoding="utf-8",
)
