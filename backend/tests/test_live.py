import sys
import time

import pytest

import app.live as live

FAKE_INTERFACES = [{"index": 1, "name": r"\Device\NPF_{TEST}", "description": "Test NIC"}]


@pytest.fixture
def fake_dumpcap(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """A stand-in 'dumpcap' that writes a tiny file and exits, so no real capture runs."""
    script = tmp_path / "fake_dumpcap.py"
    script.write_text(
        "import sys, time\n"
        "path = sys.argv[sys.argv.index('-w') + 1]\n"
        "open(path, 'wb').write(b'\\x0a\\x0d\\x0d\\x0a' + b'\\x00' * 60)\n"
        "time.sleep(1)\n", encoding="utf-8")
    monkeypatch.setattr(live, "list_interfaces", lambda: FAKE_INTERFACES)
    monkeypatch.setattr(live, "dumpcap_executable", lambda: sys.executable)
    real_popen = live.subprocess.Popen

    def popen(args, **kwargs):
        return real_popen([sys.executable, str(script), *args[1:]], **kwargs)

    monkeypatch.setattr(live.subprocess, "Popen", popen)
    monkeypatch.setattr(live.LiveCaptureManager, "_hand_over", staticmethod(lambda session: None))
    monkeypatch.setattr(live, "manager", live.LiveCaptureManager())
    import app.api.live as api_live
    monkeypatch.setattr(api_live, "manager", live.manager)
    monkeypatch.setattr(api_live, "list_interfaces", lambda: FAKE_INTERFACES)
    monkeypatch.setattr(api_live, "dumpcap_executable", lambda: sys.executable)
    yield


def test_live_capture_is_admin_only_by_default(api, fake_dumpcap) -> None:
    assert api.client.get("/api/live/status", headers=api.as_("analyst")).status_code == 403
    assert api.client.get("/api/live/interfaces", headers=api.as_("viewer")).status_code == 403
    assert api.client.get("/api/live/interfaces", headers=api.as_("admin")).json() == FAKE_INTERFACES


def test_unknown_interfaces_and_presets_are_rejected(api, fake_dumpcap) -> None:
    headers = api.as_("admin")
    bad_iface = api.client.post("/api/live/sessions", json={"interface": "eth0; rm -rf /", "duration_seconds": 10}, headers=headers)
    assert bad_iface.status_code == 400
    bad_filter = api.client.post("/api/live/sessions", json={"interface": FAKE_INTERFACES[0]["name"], "duration_seconds": 10, "filter": "tcp port 22"},
                                 headers=headers)
    assert bad_filter.status_code == 422


def test_one_capture_at_a_time_and_audited(api, fake_dumpcap) -> None:
    headers = api.as_("admin")
    body = {"interface": FAKE_INTERFACES[0]["name"], "duration_seconds": 10, "filter": "ipsec"}
    first = api.client.post("/api/live/sessions", json=body, headers=headers)
    assert first.status_code == 201
    assert api.client.post("/api/live/sessions", json=body, headers=headers).status_code == 409
    session_id = first.json()["id"]
    for _ in range(40):
        if api.client.get(f"/api/live/sessions/{session_id}", headers=headers).json()["status"] not in ("capturing", "analysing"):
            break
        time.sleep(0.25)
    assert api.client.get(f"/api/live/sessions/{session_id}", headers=headers).json()["status"] == "completed"
    actions = {entry["action"] for entry in api.client.get("/api/audit", headers=headers).json()}
    assert "live.start" in actions
