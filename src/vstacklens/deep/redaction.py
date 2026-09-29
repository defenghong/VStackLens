from __future__ import annotations

import re
from typing import Any

from vstacklens.deep.contracts import DeepDataset


# Account names commonly appear as the user component of DOMAIN\\user and
# user@domain log identities. Treat separators around that component as token
# boundaries while still avoiding matches inside longer alphanumeric names.
_USER_TOKEN_BOUNDARY = r"(?<![\w.@-]){}(?![\w.-])"


def _redact_nested(
    value: Any,
    username_patterns: list[re.Pattern[str]],
    password_patterns: list[re.Pattern[str]],
    principal_field_pattern: re.Pattern[str],
    principal_username_patterns: list[re.Pattern[str]],
    auth_context_pattern: re.Pattern[str],
    auth_username_patterns: list[re.Pattern[str]],
) -> Any:
    if isinstance(value, str):
        for pattern in username_patterns:
            value = pattern.sub("[REDACTED]", value)
        def redact_principal(match: re.Match[str]) -> str:
            principal = match.group(2)
            if any(pattern.search(principal) for pattern in principal_username_patterns):
                return match.group(1) + "[REDACTED]"
            return match.group(0)

        value = principal_field_pattern.sub(redact_principal, value)
        def redact_auth_context(match: re.Match[str]) -> str:
            left = max(0, match.start() - 64)
            right = min(len(value), match.end() + 64)
            return "[REDACTED]" if auth_context_pattern.search(value[left:right]) else match.group(0)

        for pattern in auth_username_patterns:
            value = pattern.sub(redact_auth_context, value)
        for pattern in password_patterns:
            value = pattern.sub("[REDACTED]", value)
        return value
    if isinstance(value, list):
        return [
            _redact_nested(item, username_patterns, password_patterns, principal_field_pattern, principal_username_patterns, auth_context_pattern, auth_username_patterns)
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _redact_nested(item, username_patterns, password_patterns, principal_field_pattern, principal_username_patterns, auth_context_pattern, auth_username_patterns)
            for item in value
        )
    if isinstance(value, dict):
        return {
            key: _redact_nested(item, username_patterns, password_patterns, principal_field_pattern, principal_username_patterns, auth_context_pattern, auth_username_patterns)
            for key, item in value.items()
        }
    return value


def redact_dataset_credentials(
    dataset: DeepDataset,
    *,
    usernames: list[str] | tuple[str, ...],
    passwords: list[str] | tuple[str, ...],
) -> DeepDataset:
    """Redact workbook credentials from every serializable Deep Dataset field.

    The credential strings stay in process memory; this returns a sanitized Dataset
    that is safe to serialize to local evidence and render into customer reports.
    """
    username_patterns = [re.compile(_USER_TOKEN_BOUNDARY.format(re.escape(value)), re.IGNORECASE) for value in sorted(set(usernames), key=len, reverse=True) if value]
    password_patterns = [re.compile(re.escape(value), re.IGNORECASE) for value in sorted(set(passwords), key=len, reverse=True) if value]
    principal_field_pattern = re.compile(r"(?i)(\b(?:username|user_name|user|principal|principal_id|login|account)\b\s*[:=]\s*)([^\s,;]+)")
    principal_username_patterns = [re.compile(r"(?i)(?<![\w@])" + re.escape(value) + r"(?![\w@])") for value in sorted(set(usernames), key=len, reverse=True) if value]
    auth_context_pattern = re.compile(r"(?i)\b(?:user(?:name)?|principal|login|authentication|authenticated|account|authn|authz)\b")
    auth_username_patterns = [re.compile(r"(?i)(?<![\w.@])" + re.escape(value) + r"(?![\w.@])") for value in sorted(set(usernames), key=len, reverse=True) if value]
    if not username_patterns and not password_patterns:
        return dataset
    payload = dataset.model_dump(mode="json")
    sanitized = _redact_nested(
        payload,
        username_patterns,
        password_patterns,
        principal_field_pattern,
        principal_username_patterns,
        auth_context_pattern,
        auth_username_patterns,
    )
    return DeepDataset.model_validate(sanitized)
