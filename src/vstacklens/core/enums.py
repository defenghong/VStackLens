from enum import StrEnum


class RiskLevel(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class ConfidenceLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleResultStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class DataQuality(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    MISSING = "missing"
    PERMISSION_DENIED = "permission_denied"
    API_ERROR = "api_error"
    UNSUPPORTED_VERSION = "unsupported_version"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    EXCEPTION = "exception"


class RuleImplementationStatus(StrEnum):
    IMPLEMENTED = "implemented"
    PLANNED = "planned"
    OPTIONAL_PLUGIN = "optional_plugin"
    DEPRECATED = "deprecated"


class RuleExecutionMode(StrEnum):
    DEFAULT_ENABLED = "default_enabled"
    DISABLED_BY_DEFAULT = "disabled_by_default"
    OPTIONAL_ENABLED = "optional_enabled"
    PLUGIN_REQUIRED = "plugin_required"
