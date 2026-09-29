"""Stage-six vSAN and server compatibility helpers."""

from .server import ServerCompatibilityResult, match_server_model
from .vsan import VsanCompatibilityResult, VsanContext, evaluate_vsan_compatibility

__all__ = [
    "ServerCompatibilityResult",
    "VsanCompatibilityResult",
    "VsanContext",
    "evaluate_vsan_compatibility",
    "match_server_model",
]
