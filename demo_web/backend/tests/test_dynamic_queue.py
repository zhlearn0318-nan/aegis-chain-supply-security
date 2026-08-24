from __future__ import annotations

import sqlite3
import threading
import time

from fastapi.testclient import TestClient

from backend import app as gateway


ADMIN_TOKEN = "test-admin-token-2026-memory-only"
ADMIN_HEADER = {"X-Aegis-Admin-Token": ADMIN_TOKEN}


def configure_isolated_runtime(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(gateway, "DB_PATH", tmp_path / "scan_history.db")
    monkeypatch.setattr(gateway, "DYNAMIC_JOB_ROOT", tmp_path / "dynamic-audit-jobs")
    monkeypatch.setattr(gateway, "skill_closure_is_ready", lambda: True)
    monkeypatch.setenv(gateway.ADMIN_TOKEN_ENV, ADMIN_TOKEN)


def wait_until(predicate, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition did not become true before timeout")


def test_fifo_single_execution_and_active_deduplication(monkeypatch, tmp_path) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    first_started = threading.Event()
    release_first = threading.Event()
    execution_order: list[str] = []
    active = 0
    max_active = 0
    state_lock = threading.Lock()

    def controlled_worker(job_id: str) -> None:
        nonlocal active, max_active
        job = gateway.load_dynamic_audit_job(job_id)
        assert job is not None
        with state_lock:
            active += 1
            max_active = max(max_active, active)
            execution_order.append(job["audit_type"])
        if len(execution_order) == 1:
            first_started.set()
            assert release_first.wait(5)
        gateway.update_dynamic_audit_job(
            job,
            status="completed",
            finished_at=gateway.utc_now(),
            error_code=None,
            error=None,
        )
        with state_lock:
            active -= 1

    monkeypatch.setattr(gateway, "guarded_dynamic_audit_worker", controlled_worker)

    with TestClient(gateway.app) as client:
        first = client.post("/api/v1/admin/dynamic-audits", headers=ADMIN_HEADER)
        assert first.status_code == 202
        assert first_started.wait(5)

        second = client.post(
            "/api/v1/admin/dynamic-audits/skill-closure", headers=ADMIN_HEADER
        )
        duplicate = client.post(
            "/api/v1/admin/dynamic-audits/skill-closure", headers=ADMIN_HEADER
        )
        second_job = second.json()["data"]
        duplicate_job = duplicate.json()["data"]

        assert second_job["status"] == "queued"
        assert second_job["queue_position"] == 1
        assert duplicate_job["id"] == second_job["id"]
        assert duplicate_job["deduplicated"] is True
        assert duplicate_job["dedupe_reason"] == "active"

        release_first.set()
        wait_until(
            lambda: gateway.load_dynamic_audit_job(second_job["id"])["status"]
            == "completed"
        )

    assert execution_order == ["mechanism_fixture", "skill_runtime_closure"]
    assert max_active == 1
    with sqlite3.connect(gateway.DB_PATH) as db:
        total = db.execute("SELECT COUNT(*) FROM dynamic_audits").fetchone()[0]
    assert total == 2


def test_queue_limit_returns_structured_429(monkeypatch, tmp_path) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(gateway, "DYNAMIC_QUEUE_MAX_PENDING", 0)
    started = threading.Event()
    release = threading.Event()

    def blocking_worker(job_id: str) -> None:
        started.set()
        assert release.wait(5)
        job = gateway.load_dynamic_audit_job(job_id)
        assert job is not None
        gateway.update_dynamic_audit_job(
            job, status="completed", finished_at=gateway.utc_now()
        )

    monkeypatch.setattr(gateway, "guarded_dynamic_audit_worker", blocking_worker)

    with TestClient(gateway.app) as client:
        first = client.post("/api/v1/admin/dynamic-audits", headers=ADMIN_HEADER)
        assert first.status_code == 202
        assert started.wait(5)
        rejected = client.post(
            "/api/v1/admin/dynamic-audits/skill-closure", headers=ADMIN_HEADER
        )
        release.set()

    assert rejected.status_code == 429
    assert rejected.json()["error"]["code"] == "DYNAMIC_AUDIT_QUEUE_FULL"
    assert rejected.json()["error"]["details"] == {
        "max_pending": 0,
        "queued": 0,
        "running": 1,
    }


def test_recent_terminal_job_is_deduplicated_during_cooldown(monkeypatch, tmp_path) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(gateway, "DYNAMIC_QUEUE_DEDUPE_COOLDOWN_SECONDS", 10)
    gateway.init_db()
    original = gateway.enqueue_dynamic_audit_job()
    assert gateway.claim_next_dynamic_audit_job() == original["id"]
    running = gateway.load_dynamic_audit_job(original["id"])
    gateway.update_dynamic_audit_job(
        running, status="completed", finished_at=gateway.utc_now()
    )

    duplicate = gateway.enqueue_dynamic_audit_job()

    assert duplicate["id"] == original["id"]
    assert duplicate["deduplicated"] is True
    assert duplicate["dedupe_reason"] == "cooldown"
    with sqlite3.connect(gateway.DB_PATH) as db:
        assert db.execute("SELECT COUNT(*) FROM dynamic_audits").fetchone()[0] == 1


def test_atomic_claim_allows_only_one_running_job(monkeypatch, tmp_path) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    gateway.init_db()
    first = gateway.enqueue_dynamic_audit_job("mechanism_fixture")
    second = gateway.enqueue_dynamic_audit_job("skill_runtime_closure")
    claimed: list[str] = []
    barrier = threading.Barrier(3)

    def claim() -> None:
        barrier.wait()
        result = gateway.claim_next_dynamic_audit_job()
        if result:
            claimed.append(result)

    workers = [threading.Thread(target=claim) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(5)

    assert claimed == [first["id"]]
    assert gateway.load_dynamic_audit_job(first["id"])["status"] == "running"
    assert gateway.load_dynamic_audit_job(second["id"])["status"] == "queued"


def test_restart_recovery_fails_running_and_retains_queue(monkeypatch, tmp_path) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    gateway.init_db()
    running = gateway.build_dynamic_audit_job("mechanism_fixture")
    running.update(
        status="running",
        started_at=gateway.utc_now(),
        attempt=1,
        queue_reason=None,
    )
    queued = gateway.build_dynamic_audit_job("skill_runtime_closure")
    gateway.save_dynamic_audit_job(running)
    gateway.save_dynamic_audit_job(queued)

    result = gateway.recover_interrupted_dynamic_audit_jobs()
    failed = gateway.load_dynamic_audit_job(running["id"])
    retained = gateway.load_dynamic_audit_job(queued["id"])

    assert result == {"failed_running": 1, "retained_queued": 1}
    assert failed["status"] == "failed"
    assert failed["error_code"] == "DYNAMIC_AUDIT_INTERRUPTED_BY_RESTART"
    assert failed["finished_at"] is not None
    assert retained["status"] == "queued"
    assert retained["recovered_after_restart"] is True
    assert retained["recovery_note"] == "queued_job_retained_for_fifo_resume"
    assert gateway.claim_next_dynamic_audit_job() == queued["id"]


def test_non_finalizing_worker_is_failed_closed(monkeypatch, tmp_path) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    gateway.init_db()
    job = gateway.enqueue_dynamic_audit_job()
    assert gateway.claim_next_dynamic_audit_job() == job["id"]

    gateway.finalize_incomplete_dynamic_audit_job(job["id"])
    finalized = gateway.load_dynamic_audit_job(job["id"])

    assert finalized["status"] == "failed"
    assert finalized["error_code"] == "DYNAMIC_AUDIT_WORKER_DID_NOT_FINALIZE"
    assert finalized["finished_at"] is not None
