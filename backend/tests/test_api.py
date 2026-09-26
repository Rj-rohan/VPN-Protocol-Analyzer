from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.models import AuditLog, Capture
from app.packet.tshark import TSharkService
from pcap_builder import esp, ikev1_main_mode, udp, v4, write_pcap

needs_tshark = pytest.mark.skipif(not TSharkService().capabilities().available, reason="TShark is not installed")


def legacy_capture(tmp_path: Path, name: str = "legacy.pcap", spi: int = 0x1000) -> bytes:
    frames = [
        v4("10.0.0.1", "10.0.0.2", 17, udp(500, 500, ikev1_main_mode()), 1.0),
        v4("10.0.0.2", "10.0.0.1", 17, udp(500, 500, ikev1_main_mode(responder=True)), 1.1),
        *(v4("10.0.0.1" if n % 2 else "10.0.0.2", "10.0.0.2" if n % 2 else "10.0.0.1", 50, esp(spi, n, size=60 + n % 7 * 90), 2.0 + n * 0.05)
          for n in range(1, 41)),
    ]
    return write_pcap(tmp_path / name, frames).read_bytes()


def test_endpoints_require_authentication(api) -> None:
    assert api.client.get("/api/analyses").status_code == 401
    assert api.client.post("/api/captures/upload", files={"file": ("a.pcap", b"x")}).status_code == 401
    assert api.client.get("/api/analyses", headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_viewer_cannot_upload(api, tmp_path: Path) -> None:
    assert api.upload("viewer", legacy_capture(tmp_path)).status_code == 403


def test_rejects_wrong_extension_and_non_capture_content(api) -> None:
    assert api.upload("analyst", b"hello", "notes.txt").status_code == 400
    response = api.upload("analyst", b"MZ\x90\x00 definitely not a capture", "evil.pcap")
    assert response.status_code == 400
    assert "not a pcap" in response.json()["detail"]


def test_filename_is_sanitised(api, tmp_path: Path) -> None:
    response = api.upload("analyst", legacy_capture(tmp_path), "../../etc/..\\passwd.pcap")
    assert response.status_code == 202
    with api.Session() as db:
        stored = Path(db.scalar(select(Capture.stored_path)))
    assert stored.parent.name == "pcaps"
    assert ".." not in stored.name and "/" not in stored.name and "\\" not in stored.name


@needs_tshark
def test_upload_runs_full_analysis(api, tmp_path: Path) -> None:
    response = api.upload("analyst", legacy_capture(tmp_path))
    assert response.status_code == 202
    analysis_id = response.json()["analysis_id"]

    detail = api.client.get(f"/api/analyses/{analysis_id}", headers=api.as_("analyst")).json()
    assert detail["status"] == "completed"
    assert detail["ike_version"] == "IKEv1"
    assert detail["risk_level"] in ("High", "Critical")
    features = detail["result"]["features"]
    assert features["traffic"]["features"]["flow_packet_count"] == 40
    assert detail["result"]["traffic_prediction"]["status"] in ("predicted", "unavailable")
    rules = {f["rule_id"] for f in detail["result"]["security"]["findings"]}
    assert {"PROTO-001", "CRYPTO-001", "CRYPTO-002", "META-002"} <= rules

    summary = api.client.get("/api/dashboard/summary", headers=api.as_("analyst")).json()
    assert summary["total_analyses"] == 1
    assert summary["ipsec_detections"] == 1
    assert summary["high_risk_captures"] == 1
    assert summary["findings_by_severity"]["High"] >= 3


@needs_tshark
def test_same_filename_different_content_is_stored_separately(api, tmp_path: Path) -> None:
    first, second = legacy_capture(tmp_path, "a.pcap", 0x1), legacy_capture(tmp_path, "b.pcap", 0x2)
    for content in (first, second):
        assert api.upload("analyst", content, "capture.pcap").status_code == 202
    with api.Session() as db:
        paths = [Path(p) for p in db.scalars(select(Capture.stored_path)).all()]
    assert len(set(paths)) == 2
    assert sorted(path.read_bytes() for path in paths) == sorted([first, second])
    assert not list((tmp_path / "pcaps").glob(".upload-*"))


@needs_tshark
def test_analysts_only_see_their_own_analyses(api, tmp_path: Path) -> None:
    analysis_id = api.upload("analyst", legacy_capture(tmp_path)).json()["analysis_id"]

    assert api.client.get(f"/api/analyses/{analysis_id}", headers=api.as_("analyst2")).status_code == 404
    assert api.client.get("/api/analyses", headers=api.as_("analyst2")).json()["total"] == 0
    assert api.client.get(f"/api/analyses/{analysis_id}", headers=api.as_("viewer")).status_code == 200
    assert api.client.get(f"/api/analyses/{analysis_id}", headers=api.as_("admin")).status_code == 200
    assert api.client.delete(f"/api/analyses/{analysis_id}", headers=api.as_("viewer")).status_code == 403


@needs_tshark
def test_delete_removes_capture_file_and_is_audited(api, tmp_path: Path) -> None:
    analysis_id = api.upload("analyst", legacy_capture(tmp_path)).json()["analysis_id"]
    with api.Session() as db:
        stored = Path(db.scalar(select(Capture.stored_path)))
    assert stored.exists()

    assert api.client.delete(f"/api/analyses/{analysis_id}", headers=api.as_("analyst")).status_code == 204
    assert not stored.exists()
    assert api.client.get(f"/api/analyses/{analysis_id}", headers=api.as_("admin")).status_code == 404
    with api.Session() as db:
        actions = set(db.scalars(select(AuditLog.action)).all())
    assert {"login", "capture.upload", "analysis.delete"} <= actions
