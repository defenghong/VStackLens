from __future__ import annotations

import threading
import time
import os
from typing import Any, Callable


class LocalResourceMonitor:
    """Sample this local process only; it never connects to or probes VMware hosts."""

    def __init__(self, sampler: Callable[[], dict[str, Any]], *, interval_seconds: float = 0.5) -> None:
        self.sampler = sampler
        self.interval_seconds = max(0.1, float(interval_seconds))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stopped = False
        self._lock = threading.Lock()
        self._samples: list[tuple[float, dict[str, Any]]] = []

    def _sample(self) -> None:
        sampled_at = time.monotonic()
        try:
            payload = self.sampler()
        except Exception as exc:  # noqa: BLE001 - monitoring cannot abort collection.
            payload = {"status": "unavailable", "reason": type(exc).__name__}
        with self._lock:
            self._samples.append((sampled_at, payload))

    def start(self) -> None:
        if self._thread is not None or self._stopped:
            return
        self._sample()
        self._thread = threading.Thread(target=self._run, name="deep-local-resource-monitor", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self._sample()

    def stop(self) -> dict[str, Any]:
        if self._stopped:
            return self._summary()
        if self._thread is None:
            self.start()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval_seconds * 3))
        self._sample()
        self._stopped = True
        return self._summary()

    def latest_sample(self) -> dict[str, Any]:
        with self._lock:
            samples = list(self._samples[-2:])
        if not samples:
            return {"status": "unavailable"}
        latest = dict(samples[-1][1])
        if len(samples) == 2 and all(item[1].get("status") == "ok" for item in samples):
            elapsed = samples[-1][0] - samples[0][0]
            if elapsed > 0:
                first, last = samples[0][1], samples[1][1]
                cpu = (float(last.get("cpu_user_sec") or 0) + float(last.get("cpu_system_sec") or 0)) - (float(first.get("cpu_user_sec") or 0) + float(first.get("cpu_system_sec") or 0))
                one_core = max(cpu, 0.0) / elapsed * 100.0
                latest["cpu_percent_of_one_core"] = one_core
                latest["cpu_percent_of_machine"] = one_core / max(os.cpu_count() or 1, 1)
        return latest

    def _summary(self) -> dict[str, Any]:
        with self._lock:
            samples = list(self._samples)
        valid = [(at, item) for at, item in samples if item.get("status") == "ok"]
        if not valid:
            return {"status": "unavailable", "sample_count": len(samples), "reason": "no successful local resource samples"}
        rss_values = [int(item.get("rss_bytes") or 0) for _, item in valid]
        peak_cpu = 0.0
        for (left_at, left), (right_at, right) in zip(valid, valid[1:]):
            elapsed = right_at - left_at
            if elapsed <= 0:
                continue
            cpu_delta = (float(right.get("cpu_user_sec") or 0) + float(right.get("cpu_system_sec") or 0)) - (float(left.get("cpu_user_sec") or 0) + float(left.get("cpu_system_sec") or 0))
            peak_cpu = max(peak_cpu, max(cpu_delta, 0.0) / elapsed * 100.0)
        cpu_count = max(os.cpu_count() or 1, 1)
        first, last = valid[0][1], valid[-1][1]
        return {
            "status": "ok" if len(valid) >= 2 else "limited",
            "sample_count": len(valid),
            "sampling_interval_seconds": self.interval_seconds,
            "sampled_duration_seconds": round(valid[-1][0] - valid[0][0], 3),
            "peak_cpu_percent_of_one_core": round(peak_cpu, 2),
            "peak_cpu_percent_of_machine": round(peak_cpu / cpu_count, 2),
            "logical_cpu_count": cpu_count,
            "peak_rss_bytes": max(rss_values),
            "disk_read_bytes": max(int(last.get("read_bytes") or 0) - int(first.get("read_bytes") or 0), 0),
            "disk_write_bytes": max(int(last.get("write_bytes") or 0) - int(first.get("write_bytes") or 0), 0),
            "source": "local process sampler",
        }


class LatchedResourceGuard:
    """Keep a resource stop decision active for the rest of one collection run."""

    def __init__(self, check: Callable[[], str | None]) -> None:
        self.check = check
        self.reason: str | None = None

    def __call__(self) -> str | None:
        if self.reason:
            return self.reason
        self.reason = self.check()
        return self.reason
