import json
from pathlib import Path

import pytest

from app.packet.tshark import TSharkService
from app.reports.llm import ungrounded_claims
from app.reports.narrative import facts, template_narrative
from test_api import legacy_capture

needs_tshark = pytest.mark.skipif(not TSharkService().capabilities().available, reason="TShark is not installed")


@needs_tshark
def test_generate_and_download_both_reports(api, tmp_path: Path) -> None:
    analysis_id = api.upload("analyst", legacy_capture(tmp_path)).json()["analysis_id"]
    headers = api.as_("analyst")

    for kind in ("executive", "technical"):
        created = api.client.post(f"/api/analyses/{analysis_id}/reports", json={"kind": kind}, headers=headers)
        assert created.status_code == 201, created.text
        assert created.json()["narrative_source"].startswith("deterministic template")
        download = api.client.get(f"/api/reports/{created.json()['id']}/download", headers=headers)
        assert download.status_code == 200
        assert download.headers["content-type"] == "application/pdf"
        assert download.content.startswith(b"%PDF")
        assert len(download.content) > 3000

    # Other analysts cannot fetch the report.
    report_id = created.json()["id"]
    assert api.client.get(f"/api/reports/{report_id}/download", headers=api.as_("analyst2")).status_code == 404
    detail = api.client.get(f"/api/analyses/{analysis_id}", headers=headers).json()
    assert {r["kind"] for r in detail["reports"]} == {"executive", "technical"}


@needs_tshark
def test_narrative_is_built_from_structured_output(api, tmp_path: Path) -> None:
    analysis_id = api.upload("analyst", legacy_capture(tmp_path)).json()["analysis_id"]
    body = api.client.get(f"/api/analyses/{analysis_id}/narrative", headers=api.as_("analyst")).json()

    narrative = body["narrative"]
    assert "IKEv1" in narrative["executive_summary"]
    assert any("IKEv2" in item for item in narrative["remediation"])
    assert body["facts"]["configuration"]["dh_group"]["value"] == "DH2 (MODP-1024)"
    # The deterministic narrative itself must pass the grounding check applied to LLM output.
    text = " ".join([narrative["executive_summary"], narrative["technical_explanation"], *narrative["remediation"]])
    assert ungrounded_claims(text, json.dumps(body["facts"], indent=1, sort_keys=True)) == []


def test_grounding_check_rejects_invented_values() -> None:
    f = {"configuration": {"encryption": {"value": "AES-256-GCM-16"}, "dh_group": {"value": "DH14 (MODP-2048)"},
                           "prf": {"value": "HMAC-SHA2-256"}}, "assessment": {"security_score": 85}}
    facts_json = json.dumps(f, indent=1, sort_keys=True)

    assert ungrounded_claims("Uses AES-256-GCM-16 with DH14 and SHA-256; score 85/100.", facts_json) == []
    assert ungrounded_claims("Uses 3DES with DH2 (MODP-1024); score 40/100.", facts_json) == ["3DES", "40/100", "DH2", "MODP-1024"]


def test_template_handles_capture_without_ipsec() -> None:
    f = facts({"packet_count": 12, "features": {"detection": {"ipsec_detected": False}}}, "web.pcap")
    narrative = template_narrative(f)
    assert "no IKE, ESP or AH" in narrative["executive_summary"]
    assert narrative["remediation"] == []
