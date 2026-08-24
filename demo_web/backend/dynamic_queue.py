from __future__ import annotations

import threading
from collections.abc import Callable


class DynamicAuditScheduler:
    """Wake-driven, single-consumer scheduler over a persistent job store.

    The store remains the source of truth.  ``claim_next`` must atomically enforce
    the global running-job invariant so accidentally starting two schedulers does
    not increase execution concurrency.
    """

    def __init__(
        self,
        *,
        claim_next: Callable[[], str | None],
        run_job: Callable[[str], None],
        finalize_incomplete: Callable[[str], None],
        idle_wait_seconds: float = 0.25,
    ) -> None:
        self._claim_next = claim_next
        self._run_job = run_job
        self._finalize_incomplete = finalize_incomplete
        self._idle_wait_seconds = idle_wait_seconds
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._wake.set()
            self._thread = threading.Thread(
                target=self._loop,
                name="aegis-dynamic-audit-worker",
                daemon=True,
            )
            self._thread.start()

    def notify(self) -> None:
        self._wake.set()

    def stop(self, *, wait: bool = True, timeout_seconds: float = 30.0) -> None:
        with self._lock:
            thread = self._thread
            self._stop.set()
            self._wake.set()
        if wait and thread is not None:
            thread.join(timeout_seconds)
        with self._lock:
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            job_id = self._claim_next()
            if job_id is None:
                self._wake.wait(self._idle_wait_seconds)
                self._wake.clear()
                continue
            try:
                self._run_job(job_id)
            except Exception:
                # The persistent finalizer records a fail-closed terminal state.
                pass
            finally:
                self._finalize_incomplete(job_id)
