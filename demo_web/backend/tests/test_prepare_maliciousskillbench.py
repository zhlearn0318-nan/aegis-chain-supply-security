from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tools.datasets.prepare_maliciousskillbench_source_disjoint import (
    IntakeError,
    public_text,
    safe_case_id,
    sha256_bytes,
)


def test_safe_case_id_normalizes_without_allowing_paths() -> None:
    assert safe_case_id("ASB04_000001") == "asb04_000001"
    for value in ("../escape", "folder/case", "C:\\case", "", "a" * 81):
        with pytest.raises(IntakeError):
            safe_case_id(value)


def test_public_text_prefers_exact_released_text() -> None:
    text, field = public_text({"benchmark_id": "case", "skill_text": "hello"})
    assert text == "hello"
    assert field == "skill_text"


def test_public_text_verifies_sanitized_hash() -> None:
    content = "sanitized"
    row = {
        "benchmark_id": "case",
        "skill_text": None,
        "public_skill_text": content,
        "public_text_sha256": sha256_bytes(content.encode("utf-8")),
    }
    assert public_text(row) == (content, "public_skill_text")
    row["public_text_sha256"] = hashlib.sha256(b"other").hexdigest()
    with pytest.raises(IntakeError):
        public_text(row)


def test_public_text_fails_closed_when_no_released_text() -> None:
    with pytest.raises(IntakeError):
        public_text({"benchmark_id": "case", "skill_text": None, "public_skill_text": None})
