from __future__ import annotations

from backend.dynamic_audit.skill_sandbox import serialize_dynamic_evaluation
from tools.evaluation.run_m15_e03_dynamic_round_ablation import fuse, percentile, prefix_evaluation


def test_percentile_uses_nearest_rank() -> None:
    assert percentile([1, 2, 3, 4, 5], 0.95) == 5


def test_fusion_is_monotonic_and_unknown_fails_closed() -> None:
    assert fuse("REVIEW", "ALLOW") == "REVIEW"
    assert fuse("ALLOW", "BLOCK") == "BLOCK"
    assert fuse("UNKNOWN", "ALLOW") == "BLOCK"


def test_prefix_evaluation_uses_only_selected_rounds() -> None:
    payload = {
        "runner": {
            "telemetry_complete": True,
            "rounds": [
                {"id": "typical", "execution_status": "completed", "duration_ms": 10},
                {"id": "edge", "execution_status": "completed", "duration_ms": 20},
                {"id": "adversarial", "execution_status": "completed", "duration_ms": 30},
            ],
            "events": [
                {"type": "telemetry.ready", "round": "typical"},
                {"type": "os.system", "command": "controlled", "round": "adversarial"},
            ],
        }
    }
    d1 = prefix_evaluation(payload, ("typical",))
    d3 = prefix_evaluation(payload, ("typical", "edge", "adversarial"))
    assert d1["evaluation"]["decision"] == "ALLOW"
    assert d3["evaluation"]["decision"] == "BLOCK"
    assert d1["round_duration_ms"] == 10
    assert d3["round_duration_ms"] == 60


def test_prefix_evaluation_accepts_node_round_schema() -> None:
    payload = {
        "runner": {
            "telemetry_complete": True,
            "rounds": [
                {"id": "typical", "exit_code": 0, "timed_out": False},
                {"id": "edge", "exit_code": 0, "timed_out": False},
                {"id": "adversarial", "exit_code": 0, "timed_out": False},
            ],
            "events": [{"type": "telemetry.ready", "round": "typical"}],
        }
    }
    result = prefix_evaluation(payload, ("typical",))
    assert result["evaluation"]["decision"] == "ALLOW"
