from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_active_entrypoints_delegate_status_to_one_canonical_file() -> None:
    current = read("CURRENT_STATUS.md")
    assert "唯一状态真值" in current
    assert "396 passed" in current
    assert "P0-5" in current and "真实 VM" in current
    assert "NO-GO" in current

    for relative in (
        "README.md",
        "demo_web/README.md",
        "QUICKSTART.md",
        "SECURITY.md",
    ):
        assert "CURRENT_STATUS.md" in read(relative), relative


def test_active_summaries_do_not_keep_the_previous_backend_count() -> None:
    for relative in ("README.md", "demo_web/README.md"):
        content = read(relative)
        assert "396 passed" in content
        assert "395 passed" not in content
        assert "390 passed" not in content
        assert "386 passed" not in content
        assert "383 passed" not in content
        assert "361 passed" not in content
        assert "357 passed" not in content
        assert "348 passed" not in content
        assert "341 passed" not in content
        assert "329 passed" not in content
        assert "335 passed" not in content


def test_historical_entrypoints_are_explicitly_marked_as_snapshots() -> None:
    assert read("START_HERE.md").startswith("# 历史 Cisco 复现入口")
    reproduction = read("REPRODUCTION_REPORT.md")
    assert "历史报告" in reproduction[:300]
    review = read("demo_web/docs/M5_供应链安全系统真实可用性评委与工程审查.md")
    assert "审查快照" in review[:400]
    assert "CURRENT_STATUS.md" in review[:400]


def test_document_indexes_define_current_and_historical_precedence() -> None:
    assert "历史时间截面" in read("docs/README.md")
    demo_index = read("demo_web/docs/README.md")
    assert "唯一当前状态" in demo_index
    assert "M1–M4" in demo_index


def test_dynamic_queue_contract_is_documented() -> None:
    contract = read("demo_web/docs/API_V1_CONTRACT.md")
    for required in (
        "queue_position",
        "dedupe_reason",
        "DYNAMIC_AUDIT_QUEUE_FULL",
        "DYNAMIC_AUDIT_INTERRUPTED_BY_RESTART",
        "DYNAMIC_AUDIT_WORKER_DID_NOT_FINALIZE",
    ):
        assert required in contract


def test_active_truth_documents_do_not_contain_developer_profile_path() -> None:
    for relative in (
        "CURRENT_STATUS.md",
        "README.md",
        "demo_web/README.md",
        "QUICKSTART.md",
        "SECURITY.md",
        "demo_web/docs/API_V1_CONTRACT.md",
    ):
        assert "C:\\Users\\23684" not in read(relative), relative
