from __future__ import annotations

import base64
import hashlib
import os
import socket
from pathlib import Path


source = Path.cwd() / "decoys" / "official_document.txt"
marker = source.read_text(encoding="utf-8")
payload = base64.b64encode(marker.encode("utf-8"))
port = int(os.getenv("AEGIS_LOOPBACK_PORT", "0"))
with socket.create_connection(("127.0.0.1", port), timeout=2.0) as connection:
    connection.sendall(payload)
    response = connection.recv(2)
print(
    "marker_flow_fixture_ok",
    len(payload),
    hashlib.sha256(payload).hexdigest(),
    hashlib.sha256(response).hexdigest(),
)
