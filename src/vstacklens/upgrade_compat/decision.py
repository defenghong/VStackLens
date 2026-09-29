"""Shared aggregation only; VCG/vSAN evidence remains separate in payloads."""
PASSING = {"CERTIFIED", "CERTIFIED_NO_FIRMWARE_REQUIREMENT", "DRIVER_VERSION_NOT_LATEST"}
BLOCKING = {"NOT_CERTIFIED", "DRIVER_NOT_CERTIFIED", "DRIVER_VERSION_BELOW_MINIMUM", "FIRMWARE_MISMATCH", "VSAN_QUEUE_DEPTH_LOW", "VSAN_MODE_MISMATCH"}


def effective_match(device):
    base = dict((device.get("matches") or {}).get("vcg") or {})
    vsan = device.get("vsan") or {}
    code = vsan.get("status")
    if code in {"VSAN_QUEUE_DEPTH_LOW", "VSAN_MODE_MISMATCH"}:
        return {**base, "status": code, "detail": vsan.get("detail")}
    if base.get("status") in PASSING and code not in {None, "", "VSAN_NOT_APPLICABLE", "VSAN_CERTIFIED"}:
        return {**base, "status": code, "detail": vsan.get("detail")}
    return base
