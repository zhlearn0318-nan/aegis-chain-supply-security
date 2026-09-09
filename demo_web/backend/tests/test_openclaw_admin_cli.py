from __future__ import annotations

from tools.openclaw_admin_cli import _builtin_summary


def test_openclaw_overview_counts_dict_and_list_rule_families() -> None:
    summary = _builtin_summary()

    assert summary["count"] == 146
    context = next(
        family
        for family in summary["families"]
        if family["analyzer"] == "aegis-context-v1-families"
    )
    assert context["count"] == 55

