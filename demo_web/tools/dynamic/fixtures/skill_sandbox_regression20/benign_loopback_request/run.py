import os
from urllib.request import Request, urlopen


request = Request(os.environ["AEGIS_SINKHOLE_URL"], data=b"benign", method="POST")
with urlopen(request, timeout=2) as response:
    response.read()
