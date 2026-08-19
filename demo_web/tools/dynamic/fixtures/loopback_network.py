from __future__ import annotations

import hashlib
import os
import socket


port = int(os.getenv("AEGIS_LOOPBACK_PORT", "0"))
payload = os.getenv("AEGIS_LOOPBACK_PAYLOAD", "").encode("utf-8")
with socket.create_connection(("127.0.0.1", port), timeout=2.0) as connection:
    connection.sendall(payload)
    response = connection.recv(2)
print(
    "network_fixture_ok",
    len(payload),
    hashlib.sha256(payload).hexdigest(),
    hashlib.sha256(response).hexdigest(),
)
