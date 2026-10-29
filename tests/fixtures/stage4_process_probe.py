"""Public argv only; fake session secrets originate inside the offline child."""
from datetime import datetime, timedelta
from pathlib import Path
import sys

from vstacklens.application.batch_inspection import BatchInspectionService, SessionCredential
from vstacklens.application.scheduled_inspection import ScheduledInspectionService
from vstacklens.application.inspection_service import InspectionService
from vstacklens.application.inspection_runner import InspectionRunner

path, sid = Path(sys.argv[1]), sys.argv[2]
class NeverLive:
    def __init__(self, *args, **kwargs): pass
    def precheck(self): raise AssertionError("No live SDK authorized")
    def collect(self, *args, **kwargs): raise AssertionError("No live SDK authorized")
batch = BatchInspectionService(path, service_factory=lambda: InspectionService(runner=InspectionRunner(collector_factory=NeverLive)))
now = datetime.fromisoformat("2026-10-13T00:59:58+00:00")
mono = 1.0
service = ScheduledInspectionService(path, batch_manager=batch, clock=lambda: now, monotonic=lambda: mono)
plan = service.store.get(sid)
credentials = {t["environment_id"]: SessionCredential(t["username"], "OFFLINE-PROCESS-SECRET-" + t["environment_id"]) for t in plan["targets"]}
service.authorize(sid, credentials, consent=True)
service.tick()
print("READY", flush=True)
assert sys.stdin.readline().strip() == "GO"
now += timedelta(seconds=2); mono += 2
trigger = service.tick()
print("SUBMITTED" if trigger else "BLOCKED", flush=True)
assert sys.stdin.readline().strip() == "QUIT"
service.finish_shutdown()
assert not service._grants and not service.batch._credentials
print("CLEAN", flush=True)
