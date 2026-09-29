from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from vstacklens.application.paths import app_data_dir


@dataclass(frozen=True, slots=True)
class AppStatus:
    code: str
    label: str


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    min_length: int = 8
    require_digit: bool = False
    require_mixed_case: bool = False
    require_special: bool = False


class AuthService:
    DEFAULT_USERNAME = "admin"
    DEFAULT_PASSWORD = "admin"
    HASH_ALGORITHM = "pbkdf2_sha256"
    HASH_ITERATIONS = 260_000

    def __init__(self, state_path: Path | None = None) -> None:
        self.state_path = state_path or app_data_dir() / "config" / "auth_state.json"

    def validate_login(self, username: str, password: str) -> bool:
        state = self._ensure_state()
        account = state.get("account") or {}
        expected_username = str(account.get("username") or self.DEFAULT_USERNAME)
        if username.strip() != expected_username:
            return False
        return self._verify_password(password, account)

    def get_app_status(self) -> AppStatus:
        return AppStatus(code="local_deployment", label="本地部署")

    def load_saved_username(self) -> str:
        payload = self._ensure_state()
        return str(payload.get("saved_username") or "")

    def save_saved_username(self, username: str | None) -> None:
        payload = self._ensure_state()
        payload["saved_username"] = (username or "").strip()
        self._write_state(payload)

    def is_default_password_active(self, username: str | None = None) -> bool:
        state = self._ensure_state()
        account = state.get("account") or {}
        if username and username.strip() != str(account.get("username") or self.DEFAULT_USERNAME):
            return False
        if not bool(account.get("default_password")):
            return False
        return self._verify_password(self.DEFAULT_PASSWORD, account)

    def get_password_policy(self) -> PasswordPolicy:
        state = self._ensure_state()
        return self._parse_policy(state.get("password_policy") or {})

    def update_password_policy(
        self,
        *,
        min_length: int,
        require_digit: bool,
        require_mixed_case: bool,
        require_special: bool,
    ) -> PasswordPolicy:
        policy = PasswordPolicy(
            min_length=max(1, min(128, int(min_length))),
            require_digit=bool(require_digit),
            require_mixed_case=bool(require_mixed_case),
            require_special=bool(require_special),
        )
        state = self._ensure_state()
        state["password_policy"] = asdict(policy)
        self._write_state(state)
        return policy

    def change_password(self, username: str, current_password: str, new_password: str, confirm_password: str) -> tuple[bool, str]:
        if not self.validate_login(username, current_password):
            return False, "当前密码不正确。"
        if new_password != confirm_password:
            return False, "新密码和确认密码不一致。"
        ok, message = self._validate_new_password(new_password)
        if not ok:
            return False, message
        try:
            state = self._ensure_state()
            state["account"] = self._new_account(username.strip() or self.DEFAULT_USERNAME, new_password, default_password=False)
            self._write_state(state)
        except OSError:
            return False, "密码保存失败，请检查本地数据目录权限。"
        return True, "本地管理员密码已更新。"

    def _ensure_state(self) -> dict:
        payload = self._read_state()
        changed = False
        account = payload.get("account")
        if not isinstance(account, dict):
            legacy_account = self._legacy_plaintext_account(payload)
            if legacy_account is not None:
                payload["account"] = legacy_account
                payload.pop("username", None)
                payload.pop("password", None)
            else:
                payload["account"] = self._new_account(self.DEFAULT_USERNAME, self.DEFAULT_PASSWORD, default_password=True)
            changed = True
        elif account.get("hash_algorithm") != self.HASH_ALGORITHM:
            legacy_account = self._legacy_plaintext_account(account)
            if legacy_account is not None:
                payload["account"] = legacy_account
                changed = True
        if "password" in payload:
            payload.pop("password", None)
            changed = True
        if not isinstance(payload.get("password_policy"), dict):
            payload["password_policy"] = asdict(PasswordPolicy())
            changed = True
        if changed:
            self._write_state(payload)
        return payload

    def _read_state(self) -> dict:
        if not self.state_path.exists():
            return {}
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _write_state(self, payload: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _legacy_plaintext_account(self, payload: dict) -> dict | None:
        password = payload.get("password")
        if not isinstance(password, str) or not password:
            return None
        username = str(payload.get("username") or self.DEFAULT_USERNAME).strip() or self.DEFAULT_USERNAME
        return self._new_account(username, password, default_password=username == self.DEFAULT_USERNAME and password == self.DEFAULT_PASSWORD)

    def _new_account(self, username: str, password: str, *, default_password: bool) -> dict:
        salt = secrets.token_hex(16)
        return {
            "username": username,
            "hash_algorithm": self.HASH_ALGORITHM,
            "hash_iterations": self.HASH_ITERATIONS,
            "password_salt": salt,
            "password_hash": self._hash_password(password, salt),
            "default_password": bool(default_password),
        }

    def _hash_password(self, password: str, salt: str) -> str:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            self.HASH_ITERATIONS,
        )
        return base64.b64encode(digest).decode("ascii")

    def _verify_password(self, password: str, account: dict) -> bool:
        if account.get("hash_algorithm") != self.HASH_ALGORITHM:
            return False
        try:
            salt = str(account["password_salt"])
            expected = str(account["password_hash"])
            actual = self._hash_password(password, salt)
        except (KeyError, TypeError, ValueError):
            return False
        return hmac.compare_digest(actual, expected)

    def _parse_policy(self, payload: dict) -> PasswordPolicy:
        try:
            min_length = int(payload.get("min_length", 8))
        except (TypeError, ValueError):
            min_length = 8
        return PasswordPolicy(
            min_length=max(1, min(128, min_length)),
            require_digit=bool(payload.get("require_digit", False)),
            require_mixed_case=bool(payload.get("require_mixed_case", False)),
            require_special=bool(payload.get("require_special", False)),
        )

    def _validate_new_password(self, password: str) -> tuple[bool, str]:
        policy = self.get_password_policy()
        if len(password) < policy.min_length:
            return False, f"新密码至少需要 {policy.min_length} 位。"
        if policy.require_digit and not any(char.isdigit() for char in password):
            return False, "新密码需要包含数字。"
        if policy.require_mixed_case and not (any(char.islower() for char in password) and any(char.isupper() for char in password)):
            return False, "新密码需要同时包含大写和小写字母。"
        if policy.require_special and not any(not char.isalnum() for char in password):
            return False, "新密码需要包含特殊字符。"
        return True, ""
