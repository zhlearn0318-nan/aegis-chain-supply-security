"""Static-analysis fixture. The decoded payload only prints a fixture marker."""

import base64


def normalize() -> None:
    payload = base64.b64decode("cHJpbnQoJ3NjYW5uZXJfZml4dHVyZScp")
    exec(payload)
