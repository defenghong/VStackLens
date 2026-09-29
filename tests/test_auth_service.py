from __future__ import annotations

import json
from pathlib import Path

from vstacklens.application import AuthService


def test_auth_service_default_local_account_and_app_status(tmp_path: Path) -> None:
    service = AuthService(state_path=tmp_path / "auth_state.json")

    assert service.validate_login("admin", "admin")
    assert service.validate_login(" admin ", "admin")
    assert not service.validate_login("admin", "wrong")
    assert not service.validate_login("other", "admin")
    assert service.get_app_status().label == "本地部署"
    assert service.is_default_password_active("admin")

    payload = json.loads((tmp_path / "auth_state.json").read_text(encoding="utf-8"))
    account = payload["account"]
    assert account["username"] == "admin"
    assert account["hash_algorithm"] == "pbkdf2_sha256"
    assert account["password_hash"]
    assert account["password_hash"] != "admin"
    assert "DEFAULT_PASSWORD" not in payload


def test_auth_service_migrates_legacy_plaintext_account(tmp_path: Path) -> None:
    state_path = tmp_path / "auth_state.json"
    state_path.write_text(
        json.dumps({"account": {"username": "admin", "password": "admin"}, "saved_username": "admin"}),
        encoding="utf-8",
    )
    service = AuthService(state_path=state_path)

    assert service.validate_login("admin", "admin")
    assert service.is_default_password_active("admin")

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    account = payload["account"]
    assert account["hash_algorithm"] == "pbkdf2_sha256"
    assert account["password_hash"] != "admin"
    assert "password" not in account
    assert "password" not in payload


def test_auth_service_saved_username(tmp_path: Path) -> None:
    service = AuthService(state_path=tmp_path / "auth_state.json")

    assert service.load_saved_username() == ""
    service.save_saved_username("admin")
    assert service.load_saved_username() == "admin"
    service.save_saved_username("")
    assert service.load_saved_username() == ""


def test_auth_service_changes_password_and_preserves_hash(tmp_path: Path) -> None:
    service = AuthService(state_path=tmp_path / "auth_state.json")

    ok, message = service.change_password("admin", "wrong", "newpass8", "newpass8")
    assert not ok
    assert "当前密码" in message

    ok, message = service.change_password("admin", "admin", "short", "short")
    assert not ok
    assert "至少需要 8 位" in message

    ok, message = service.change_password("admin", "admin", "newpass8", "newpass8")
    assert ok
    assert "已更新" in message
    assert not service.validate_login("admin", "admin")
    assert service.validate_login("admin", "newpass8")
    assert not service.is_default_password_active("admin")


def test_default_password_can_be_changed_then_old_password_fails(tmp_path: Path) -> None:
    service = AuthService(state_path=tmp_path / "auth_state.json")

    assert service.validate_login("admin", "admin")
    assert service.is_default_password_active("admin")

    ok, message = service.change_password("admin", "admin", "newpass8", "newpass8")

    assert ok, message
    assert not service.validate_login("admin", "admin")
    assert service.validate_login("admin", "newpass8")
    assert not service.is_default_password_active("admin")


def test_auth_service_password_policy_applies_to_future_changes(tmp_path: Path) -> None:
    service = AuthService(state_path=tmp_path / "auth_state.json")
    service.update_password_policy(min_length=8, require_digit=True, require_mixed_case=True, require_special=True)

    ok, message = service.change_password("admin", "admin", "Newpass8", "Newpass8")
    assert not ok
    assert "特殊字符" in message

    ok, message = service.change_password("admin", "admin", "Newpass8!", "Newpass8!")
    assert ok, message
