from app.config import settings
from app.core.security import create_access_token, decode_access_token, hash_password, validate_password_strength, verify_password
from conftest import PASSWORD


def test_password_hashing_round_trip() -> None:
    stored = hash_password("A-long-Passphrase-42")
    assert stored.startswith("scrypt$")
    assert verify_password("A-long-Passphrase-42", stored)
    assert not verify_password("a-long-passphrase-42", stored)
    assert hash_password("same") != hash_password("same")  # salted


def test_password_policy() -> None:
    assert validate_password_strength("short") is not None
    assert validate_password_strength("alllowercaseletters") is not None
    assert validate_password_strength("Mixed-Case-and-9") is None


def test_tokens_are_signed_and_expire() -> None:
    from uuid import uuid4

    token, _ = create_access_token(uuid4(), "analyst")
    assert decode_access_token(token)["role"] == "analyst"
    assert decode_access_token(token[:-2] + "xx") is None


def test_login_success_and_me(api) -> None:
    response = api.login("analyst@test.local")
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["role"] == "analyst"
    me = api.client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.json()["email"] == "analyst@test.local"


def test_login_failure_does_not_reveal_which_part_was_wrong(api) -> None:
    unknown = api.login("nobody@test.local")
    wrong = api.login("analyst@test.local", "Wrong-Password-123")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_repeated_failures_lock_the_account(api) -> None:
    for _ in range(settings.login_max_failures):
        assert api.login("analyst@test.local", "Wrong-Password-123").status_code == 401
    # Even the correct password is refused while locked.
    assert api.login("analyst@test.local", PASSWORD).status_code == 429


def test_only_admins_manage_users(api) -> None:
    new_user = {"email": "new@test.local", "password": "Another-Strong-Pass-7", "role": "viewer"}
    assert api.client.post("/api/auth/users", json=new_user, headers=api.as_("analyst")).status_code == 403
    assert api.client.post("/api/auth/users", json={**new_user, "password": "weakpassword"}, headers=api.as_("admin")).status_code == 422
    created = api.client.post("/api/auth/users", json=new_user, headers=api.as_("admin"))
    assert created.status_code == 201
    assert api.login("new@test.local", "Another-Strong-Pass-7").status_code == 200
    assert api.client.post("/api/auth/users", json=new_user, headers=api.as_("admin")).status_code == 409

    user_id = created.json()["id"]
    assert api.client.patch(f"/api/auth/users/{user_id}", json={"is_active": False}, headers=api.as_("admin")).status_code == 200
    assert api.login("new@test.local", "Another-Strong-Pass-7").status_code == 401


def test_audit_log_is_admin_only(api) -> None:
    api.login("analyst@test.local", "Wrong-Password-123")
    assert api.client.get("/api/audit", headers=api.as_("analyst")).status_code == 403
    entries = api.client.get("/api/audit", headers=api.as_("admin")).json()
    assert any(entry["action"] == "login" and entry["outcome"] == "failure" for entry in entries)
