"""Bounded, task-local property observations for the ordinary vCenter SOAP stub.

Only explicitly selected properties share an observation within one collection.
Missing properties and faults remain uncached and use the usual SDK accessor.
There is no global patch, background work, reconnect, or cross-task state here.
"""
from __future__ import annotations

import copy
from collections import Counter
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping

from pyVmomi import vmodl
from pyVmomi.SoapAdapter import SoapStubAdapter, StubAdapterAccessorMixin
from pyVmomi.VmomiSupport import DataObject, ManagedObject


class SnapshotClosedError(RuntimeError):
    """An SDK reference outlived its collection scope."""


class SnapshotCancelledError(RuntimeError):
    """The owning collection requested cancellation."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _supported_stub(raw_stub) -> bool:
    return (isinstance(raw_stub, SoapStubAdapter)
            and str(getattr(raw_stub, "path", "")).rstrip("/") in ("/sdk", "/sdk/vimService"))


def _normalise_paths(mapping: Mapping[type, Iterable[str]]) -> dict[type, tuple[str, ...]]:
    result = {}
    for sdk_type, paths in mapping.items():
        if not isinstance(sdk_type, type) or not issubclass(sdk_type, ManagedObject):
            raise TypeError("Property snapshot types must be SDK managed object types")
        chosen = tuple(dict.fromkeys(paths))
        if any(not isinstance(path, str) or not path or "." in path for path in chosen):
            # A projection such as config.hardware cannot stand in for all of config.
            raise ValueError("Only complete, top-level SDK properties can be cached")
        result[sdk_type] = chosen
    return result


class PropertySnapshot(StubAdapterAccessorMixin):
    """Decorate one ordinary SOAP stub for one explicitly bounded observation scope.

    ``warning`` receives metadata only: SDK type, MOID, property and fault class.
    ``observations`` records real acquisition times, never accessor hit times.
    Raw SOAP connections, credentials and request contexts stay on the original
    adapter. Session-oriented retry adapters are deliberately not accepted.
    """

    def __init__(
        self,
        raw_stub: SoapStubAdapter,
        *,
        cache_paths_by_type: Mapping[type, Iterable[str]],
        cancelled: Callable[[], bool] | None = None,
        warning: Callable[[dict], None] | None = None,
        batch_size: int = 32,
        max_cached_properties: int = 8192,
    ) -> None:
        if not _supported_stub(raw_stub):
            raise TypeError("Property snapshot requires an ordinary vCenter SOAP SDK adapter")
        if not 1 <= batch_size <= 32:
            raise ValueError("Property snapshot batch_size must be between 1 and 32")
        if max_cached_properties < 1:
            raise ValueError("max_cached_properties must be positive")
        self._raw = raw_stub
        self._paths = _normalise_paths(cache_paths_by_type)
        self._cancelled = cancelled
        self._warning = warning
        self._batch_size = batch_size
        self._max_cached_properties = max_cached_properties
        self._cache: dict[tuple, object] = {}
        self._observations: list[dict] = []
        self._counts: Counter = Counter()
        self._closed = False
        self._generation = 0
        self._session_marker = self._current_session_marker()

    def __getattr__(self, name):
        # The SDK deserializer needs version, SupportServerGUIDs and related
        # adapter metadata. Keep their original implementation and ownership.
        return getattr(self._raw, name)

    def SupportServerGUIDs(self):
        return self._raw.SupportServerGUIDs()

    @property
    def counters(self) -> dict:
        return dict(self._counts, cached_properties=len(self._cache), closed=self._closed)

    @property
    def observations(self) -> list[dict]:
        return copy.deepcopy(self._observations)

    def __enter__(self):
        self._ensure_active()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def close(self) -> None:
        self._cache.clear()
        self._closed = True

    def _ensure_active(self) -> None:
        if self._closed:
            raise SnapshotClosedError("Property observation scope is closed")
        if self._cancelled is not None and self._cancelled():
            self._cache.clear()
            self._counts["cancellations"] += 1
            raise SnapshotCancelledError("Property observation scope was cancelled")
        self._refresh_session()

    def _refresh_session(self) -> None:
        marker = self._current_session_marker()
        if marker != self._session_marker:
            self._cache.clear()
            self._generation += 1
            self._session_marker = marker
            self._counts["session_invalidations"] += 1

    def _current_session_marker(self) -> tuple:
        # The cookie stays only in process memory and is never emitted. A new
        # session/target invalidates earlier observations even on the same stub.
        return tuple(getattr(self._raw, name, None)
                     for name in ("cookie", "host", "port", "path", "version"))

    def _identity(self, obj: ManagedObject) -> tuple | None:
        if not isinstance(obj, ManagedObject) or obj._GetStub() not in (self, self._raw):
            return None
        return (id(self), id(self._raw), self._generation, obj._GetServerGuid(),
                type(obj), obj._GetMoId())

    def _paths_for(self, obj: ManagedObject, mapping=None) -> tuple[str, ...]:
        mapping = self._paths if mapping is None else mapping
        return tuple(dict.fromkeys(path for sdk_type, paths in mapping.items()
                                   if isinstance(obj, sdk_type) for path in paths))

    def bind(self, obj: ManagedObject) -> ManagedObject:
        """Clone an SDK reference, preserving type, endpoint and stable identity."""
        self._ensure_active()
        if not isinstance(obj, ManagedObject):
            raise TypeError("bind requires an SDK managed object")
        stub = obj._GetStub()
        if stub not in (self._raw, self):
            raise ValueError("Cannot bind a reference from another SDK service/session")
        return type(obj)(obj._GetMoId(), self, obj._GetServerGuid())

    def _clone(self, value):
        # deepcopy must never copy a SOAP adapter (locks, credentials, pools).
        # Seed every managed reference before copying only local SDK data fields.
        memo = {id(self): self, id(self._raw): self}
        visited: set[int] = set()

        def seed(item):
            identity = id(item)
            if identity in visited:
                return
            visited.add(identity)
            if isinstance(item, ManagedObject):
                stub = item._GetStub()
                if stub in (self._raw, self):
                    stub = self
                memo[identity] = type(item)(item._GetMoId(), stub, item._GetServerGuid())
                if stub is not None:
                    memo[id(stub)] = stub
            elif isinstance(item, DataObject):
                for child in vars(item).values():
                    seed(child)
            elif isinstance(item, dict):
                for key, child in item.items():
                    seed(key)
                    seed(child)
            elif isinstance(item, (list, tuple, set, frozenset)):
                for child in item:
                    seed(child)

        seed(value)
        return copy.deepcopy(value, memo)

    def _metadata(self, obj, path=None, **extra) -> dict:
        record = {"sdk_type": type(obj).__name__, "moid": obj._GetMoId(),
                  "server_guid": obj._GetServerGuid(), "property": path}
        record.update(extra)
        return record

    def _warn(self, event, obj, path=None, fault=None) -> None:
        self._counts["warnings"] += 1
        if self._warning is not None:
            self._warning(self._metadata(obj, path, event=event,
                                         fault_type=type(fault).__name__ if fault else None))

    def _observe(self, obj, path, source, status, acquired_at, fault=None) -> None:
        self._observations.append(self._metadata(
            obj, path, source=source, status=status, acquired_at=acquired_at,
            fault_type=type(fault).__name__ if fault else None))

    def _store(self, obj, path, value, source, acquired_at) -> None:
        identity = self._identity(obj)
        if identity is None or path not in self._paths_for(obj):
            return
        key = (*identity, path)
        if key not in self._cache and len(self._cache) >= self._max_cached_properties:
            self._counts["capacity_bypasses"] += 1
            return
        try:
            stored = self._clone(value)
        except Exception as exc:
            # Copying is an optimisation, not permission to alter SDK results.
            self._warn("cache_copy_failed", obj, path, exc)
            return
        self._cache[key] = stored
        self._observe(obj, path, source, "success", acquired_at)

    def InvokeMethod(self, mo, info, args, outerStub=None):
        self._ensure_active()
        self._counts["soap_methods"] += 1
        # SoapStubAdapter intentionally returns (HTTP status, decoded value)
        # when outerStub differs. This is the SDK's documented wrapper contract.
        status, value = self._raw.InvokeMethod(mo, info, args, outerStub=self)
        # Let the caller first obtain any server continuation token. Prefetch
        # can then cancel that cursor if cancellation happened during the call.
        self._refresh_session()
        if status == 200:
            return value
        if isinstance(value, BaseException):
            raise value
        raise RuntimeError("SOAP adapter returned a non-exception fault")

    def InvokeAccessor(self, mo, info):
        self._ensure_active()
        identity = self._identity(mo)
        cacheable = identity is not None and info.name in self._paths_for(mo)
        key = (*identity, info.name) if cacheable else None
        if key is not None and key in self._cache:
            self._counts["cache_hits"] += 1
            return self._clone(self._cache[key])
        self._counts["accessor_misses"] += 1
        try:
            value = StubAdapterAccessorMixin.InvokeAccessor(self, mo, info)
            self._ensure_active()
        except (SnapshotCancelledError, SnapshotClosedError):
            raise
        except Exception as exc:
            self._counts["accessor_faults"] += 1
            self._observe(mo, info.name, "soap_accessor", "failed", _utc_now(), exc)
            raise
        if cacheable:
            self._store(mo, info.name, value, "soap_accessor", _utc_now())
            if key in self._cache:
                return self._clone(self._cache[key])
        return value

    def prefetch(self, property_collector, objects: Iterable[ManagedObject],
                 paths_by_type: Mapping[type, Iterable[str]] | None = None) -> dict:
        """Fetch bounded explicit object sets, retaining only returned properties.

        A missing object/property, a page failure or a real fault remains absent
        from the cache. Its next normal accessor therefore retains SDK fallback
        and error behaviour. Successfully received pages survive a later fault.
        """
        self._ensure_active()
        requested_paths = self._paths if paths_by_type is None else _normalise_paths(paths_by_type)
        groups: dict[tuple[type, tuple[str, ...]], list[ManagedObject]] = {}
        seen = set()
        for obj in objects:
            self._ensure_active()
            if not isinstance(obj, ManagedObject):
                raise TypeError("prefetch requires SDK managed objects")
            identity = self._identity(obj)
            if identity is None:
                self._warn("foreign_object_not_prefetched", obj)
                continue
            paths = tuple(path for path in self._paths_for(obj, requested_paths)
                          if path in self._paths_for(obj)
                          and (*identity, path) not in self._cache)
            if paths and identity not in seen:
                seen.add(identity)
                groups.setdefault((type(obj), paths), []).append(obj)
        for (sdk_type, paths), group in groups.items():
            for offset in range(0, len(group), self._batch_size):
                self._prefetch_batch(property_collector, group[offset:offset + self._batch_size],
                                     sdk_type, paths)
        return self.counters

    def _prefetch_batch(self, collector, objects, sdk_type, paths):
        self._ensure_active()
        pc = vmodl.query.PropertyCollector
        specs = [pc.FilterSpec(
            propSet=[pc.PropertySpec(type=sdk_type, all=False, pathSet=list(paths))],
            objectSet=[pc.ObjectSpec(obj=obj, skip=False) for obj in objects],
            reportMissingObjectsInResults=True)]
        wanted = {self._identity(obj): obj for obj in objects}
        received: set[tuple] = set()
        token = None
        completed = False
        tokens_seen: set[str] = set()
        page_count = 0
        try:
            self._counts["batches"] += 1
            self._counts["retrieve_calls"] += 1
            result = collector.RetrievePropertiesEx(specs, pc.RetrieveOptions(maxObjects=self._batch_size))
            while result is not None:
                # Capture the continuation token before checking cancellation,
                # so cancellation can release server-side retrieval resources.
                token = getattr(result, "token", None) or None
                acquired_at = _utc_now()
                self._ensure_active()
                self._counts["pages"] += 1
                page_count += 1
                for content in getattr(result, "objects", ()) or ():
                    returned = content.obj
                    identity = self._identity(returned)
                    original = wanted.get(identity)
                    if original is None:
                        self._warn("unexpected_object", returned)
                        continue
                    for prop in getattr(content, "propSet", ()) or ():
                        if prop.name in paths:
                            field_key = (*identity, prop.name)
                            received.add(field_key)
                            self._store(original, prop.name, prop.val, "property_collector", acquired_at)
                    for missing in getattr(content, "missingSet", ()) or ():
                        if missing.path in paths:
                            fault = getattr(missing, "fault", None)
                            if isinstance(fault, vmodl.LocalizedMethodFault):
                                wrapped_fault = getattr(fault, "fault", None)
                                fault = wrapped_fault if wrapped_fault is not None else fault
                            self._counts["missing_properties"] += 1
                            # Contradictory content cannot count as a complete
                            # property, even when propSet also named that path.
                            self._cache.pop((*identity, missing.path), None)
                            received.discard((*identity, missing.path))
                            self._observe(original, missing.path, "property_collector", "missing",
                                          acquired_at, fault)
                            self._warn("property_missing", original, missing.path, fault)
                if token is None:
                    completed = True
                    break
                if token in tokens_seen:
                    self._counts["truncated_retrievals"] += 1
                    self._warn("repeated_continuation_token", objects[0])
                    break
                tokens_seen.add(token)
                # One object may be split across returned pages. A bounded
                # generous limit prevents broken providers returning forever.
                if page_count >= max(64, len(objects) * len(paths) * 2):
                    self._counts["truncated_retrievals"] += 1
                    self._warn("continuation_page_limit", objects[0])
                    break
                self._ensure_active()
                self._counts["continue_calls"] += 1
                result = collector.ContinueRetrievePropertiesEx(token)
            if result is None:
                self._counts["truncated_retrievals"] += 1
                self._warn("empty_retrieval_page", objects[0])
        except (SnapshotCancelledError, SnapshotClosedError):
            raise
        except Exception as exc:
            self._counts["batch_faults"] += 1
            self._warn("property_batch_failed", objects[0], fault=exc)
        finally:
            if token is not None and not completed:
                try:
                    self._counts["cancel_retrieve_calls"] += 1
                    cleanup_collector = collector
                    if (isinstance(collector, ManagedObject)
                            and collector._GetStub() is self):
                        # The task is already cancelled/closed. Releasing the
                        # existing server cursor must bypass the scope guard,
                        # without reconnecting or fetching any more data.
                        cleanup_collector = type(collector)(
                            collector._GetMoId(), self._raw, collector._GetServerGuid())
                    cleanup_collector.CancelRetrievePropertiesEx(token)
                except Exception as exc:
                    self._counts["cancel_retrieve_faults"] += 1
                    self._warn("cancel_retrieval_failed", objects[0], fault=exc)
        expected = {(*identity, path) for identity in wanted for path in paths}
        self._counts["fallback_properties"] += len(expected - received)


def begin_scope(raw_stub, **kwargs) -> PropertySnapshot | None:
    """Create one scope only for the ordinary SOAP transport; leave others alone."""
    if not _supported_stub(raw_stub):
        return None
    return PropertySnapshot(raw_stub, **kwargs)
