"""Real Qt queues/threads, offline scheduler. Never destroy a running thread."""
from __future__ import annotations
import threading
import time

import pytest
from PySide6.QtCore import QObject, QCoreApplication, QEvent, QThread
from shiboken6 import isValid

from vstacklens.desktop.scheduled_inspection import ScheduledInspectionMixin, PlanTickWorker
from vstacklens.desktop.tray_runtime import TrayRuntimeMixin
from vstacklens.desktop.batch_inspection import BatchInspectionMixin
from test_stage3_batch_inspection import setup
from test_stage4_desktop_runtime import window


class OfflineClockCheck:
    def __init__(self):
        self.calls = 0
        self.block = False
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancel_requested = False
    def tick(self):
        self.calls += 1
        self.started.set()
        if self.block:
            assert self.release.wait(10), "Offline test failed to release its check thread"
        return None
    def stop(self):
        self.cancel_requested = True  # Deliberately cooperative, no force-stop.


class TickHarness(TrayRuntimeMixin, ScheduledInspectionMixin, BatchInspectionMixin, QObject):
    def __init__(self, service):
        super().__init__()
        self.service = service
        self.plan_tick_worker = None; self.plan_worker = None; self._batch_closing = False
        self.inspection_pages = type("Pages", (), {"currentIndex": lambda self: 0})()
        self.sources = []; self.errors = []
    def _plan_service(self, create=True): return self.service
    def _plan_triggered(self, trigger): assert trigger is None
    def _plan_runtime_error(self, message): self.errors.append(message)
    def _plan_tick_finished(self, *args):
        self.sources.append(args[0] if args else None)
        return super()._plan_tick_finished(*args)


def pump(app, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents(); time.sleep(.001)
    assert predicate(), "Qt completion/cleanup did not arrive"


@pytest.fixture
def controlled(qt_application_lifetime, monkeypatch):
    app = qt_application_lifetime
    service = OfflineClockCheck(); harness = TickHarness(service)
    deleted = []; unsafe = []
    original = PlanTickWorker.deleteLater
    # Safety seam for baseline reproduction: record any forbidden deletion,
    # refuse it, and leave the live thread owned until cooperative teardown.
    keep_finished = {"value": False}
    def guarded_delete(worker):
        if worker.isRunning() or not worker.wait(0):
            unsafe.append(worker)
            return
        deleted.append(worker)
        if not keep_finished["value"]: original(worker)
    monkeypatch.setattr(PlanTickWorker, "deleteLater", guarded_delete)
    yield harness, service, app, deleted, unsafe, keep_finished
    harness._batch_closing = True; service.release.set()
    for worker in harness.findChildren(QThread):
        assert worker.wait(3000), "Refusing destruction of a running test thread"
    app.processEvents()
    # Every child is ended before native deferred deletion, even on failure.
    for worker in harness.findChildren(QThread):
        assert worker.wait(0)
        original(worker)
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    app.processEvents(); harness.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_ended_check_with_queued_finished_cannot_be_replaced(controlled):
    harness, service, app, deleted, unsafe, _ = controlled
    harness._plan_timer_tick(); old = harness.plan_tick_worker
    assert old.wait(1000) and not old.isRunning()
    # Do not pump the GUI: the real native finished delivery is still queued.
    service.block = True; service.started.clear()
    harness._plan_timer_tick()
    assert harness.plan_tick_worker is old
    assert service.calls == 1
    app.processEvents()
    assert harness.plan_tick_worker is None and harness.sources == [old]
    assert deleted == [old] and not unsafe


def test_delayed_old_notification_only_cleans_its_source(controlled):
    harness, service, app, deleted, unsafe, keep = controlled
    keep["value"] = True  # Keep the ended source alive solely to emit a delayed signal.
    harness._plan_timer_tick(); old = harness.plan_tick_worker
    assert old.wait(1000)
    app.processEvents(); assert harness.plan_tick_worker is None
    service.block = True; service.started.clear()
    harness._plan_timer_tick(); new = harness.plan_tick_worker
    assert new is not old and service.started.wait(1) and new.isRunning()
    old.finished.emit(); app.processEvents()
    assert harness.plan_tick_worker is new and new.isRunning()
    assert new in harness._active_workers()
    assert all(worker is old for worker in deleted) and not unsafe
    service.release.set(); assert new.wait(1000); app.processEvents()
    assert harness.plan_tick_worker is None


def test_gui_cleanup_stays_in_exit_wait_even_after_native_run_end(controlled):
    harness, _, app, _, unsafe, _ = controlled
    harness._plan_timer_tick(); old = harness.plan_tick_worker
    assert old.wait(1000)
    assert old in harness._active_workers()
    harness._batch_closing = True
    harness._plan_timer_tick(); assert harness.plan_tick_worker is old
    app.processEvents()
    assert harness.plan_tick_worker is None and not harness._active_workers() and not unsafe


def test_continuous_checks_leave_no_live_or_invalid_member(controlled):
    harness, service, app, _, unsafe, _ = controlled
    for _ in range(20):
        harness._plan_timer_tick(); worker = harness.plan_tick_worker
        assert isValid(worker) and worker.wait(1000)
        harness._plan_timer_tick(); assert harness.plan_tick_worker is worker
        pump(app, lambda: harness.plan_tick_worker is None)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert not harness.findChildren(PlanTickWorker)
    assert service.calls == 20 and not harness._active_workers() and not unsafe


def test_finished_handler_refuses_to_delete_running_source(controlled):
    harness, service, app, deleted, unsafe, _ = controlled
    service.block = True; harness._plan_timer_tick(); worker = harness.plan_tick_worker
    assert service.started.wait(1)
    harness._plan_tick_finished(worker)
    assert harness.plan_tick_worker is worker and worker.isRunning() and not deleted and not unsafe
    service.release.set(); assert worker.wait(1000)
    pump(app, lambda: harness.plan_tick_worker is None)


@pytest.mark.parametrize("pending_only", [True, False])
def test_real_window_exit_waits_for_check_cleanup_before_credentials(window, monkeypatch, pending_only):
    widget, (_, _, settings, ids, credentials, _), app = window
    widget._plan_timer.stop(); manager = widget._plan_manager
    plan = manager.save_plan(name="仅离线线程验收", environment_ids=ids, settings=settings)
    manager.authorize(plan["schedule_id"], credentials, consent=True)
    service = OfflineClockCheck(); service.block = not pending_only
    monkeypatch.setattr(widget, "_plan_service", lambda create=True: service)
    widget._plan_timer_tick(); worker = widget.plan_tick_worker
    assert service.started.wait(1)
    if pending_only: assert worker.wait(1000)
    widget._begin_exit()
    assert not widget._exit_ready and plan["schedule_id"] in manager._grants
    assert worker in widget._active_workers() and service.cancel_requested
    widget._plan_timer_tick(); assert widget.plan_tick_worker is worker
    if not pending_only:
        app.processEvents(); assert not widget._exit_ready
        service.release.set(); assert worker.wait(1000)
    pump(app, lambda: widget._exit_ready)
    assert widget.plan_tick_worker is None and not widget._active_workers() and not manager._grants
