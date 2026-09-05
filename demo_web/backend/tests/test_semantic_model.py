from __future__ import annotations

from pathlib import Path

import pytest

from backend.semantic_model import (
    EXTERNAL_OPT_IN_ENV,
    ConfiguredSemanticProvider,
    SemanticModelError,
    load_semantic_model_config,
    _validated,
)


def test_external_provider_is_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_SEMANTIC_MODEL_MODE", "external")
    monkeypatch.delenv(EXTERNAL_OPT_IN_ENV, raising=False)
    config = load_semantic_model_config()
    with pytest.raises(SemanticModelError, match="ADMIN_OPT_IN"):
        ConfiguredSemanticProvider(config).review({"redacted_segments": ["safe"]})


def test_local_endpoint_must_be_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "model.json"
    config.write_text(
        '{"schema_version":"1.0","default_mode":"local","timeout_seconds":5,'
        '"local":{"endpoint":"http://192.0.2.1:11434","model":"x"},'
        '"external":{"enabled":false}}',
        encoding="utf-8",
    )
    monkeypatch.delenv("AEGIS_SEMANTIC_MODEL_MODE", raising=False)
    with pytest.raises(SemanticModelError, match="LOOPBACK"):
        load_semantic_model_config(config)


def test_local_percentage_confidence_is_normalized() -> None:
    result = _validated({"risk": "suspicious", "confidence": 85, "reason_codes": ["concealment"]})
    assert result["confidence"] == 0.85
