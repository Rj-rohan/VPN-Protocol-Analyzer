"""The LLM explanation layer, with the Anthropic client stubbed out (no network)."""
import json
from types import SimpleNamespace

import anthropic
import pytest

from app.config import settings
from app.reports import llm

FACTS = {
    "configuration": {"ike_version": {"value": "IKEv1"}, "dh_group": {"value": "DH2 (MODP-1024)"}, "encryption": {"value": "AES-128-CBC"}},
    "assessment": {"security_score": 35, "risk_level": "Critical"},
    # Real facts carry each finding's recommendation, which grounds remediation advice such as "IKEv2".
    "findings": [{"rule_id": "PROTO-001", "title": "Legacy IKE version",
                  "recommendation": "Migrate to IKEv2 with an approved modern proposal set and remove IKEv1 where possible."}],
}


class FakeMessages:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def fake_client(monkeypatch, text: str, stop_reason: str = "end_turn") -> FakeMessages:
    response = SimpleNamespace(stop_reason=stop_reason, model="claude-opus-5", content=[SimpleNamespace(type="text", text=text)])
    messages = FakeMessages(response)
    monkeypatch.setattr(anthropic, "Anthropic", lambda **_: SimpleNamespace(beta=SimpleNamespace(messages=messages)))
    monkeypatch.setattr(settings, "anthropic_api_key", "test-key")
    monkeypatch.setattr(settings, "llm_enabled", True)
    return messages


def narrative(summary: str) -> str:
    return json.dumps({"executive_summary": summary, "technical_explanation": "IKEv1 with DH2 (MODP-1024).", "remediation": ["Move to IKEv2."]})


def test_disabled_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    result, note = llm.generate(FACTS)
    assert result is None and "not set" in note


def test_grounded_output_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = fake_client(monkeypatch, narrative("The VPN uses IKEv1 with AES-128-CBC and scores 35/100 (PROTO-001)."))
    result, note = llm.generate(FACTS)

    assert result is not None and note == "llm:claude-opus-5"
    request = calls.calls[0]
    assert request["model"] == settings.llm_model
    assert request["betas"] == ["server-side-fallback-2026-07-01"] and request["fallbacks"] == "default"
    assert request["output_config"]["format"]["type"] == "json_schema"
    # Only the structured facts are sent, never packets.
    assert "Analyzer output" in request["messages"][0]["content"] and "PROTO-001" in request["messages"][0]["content"]


def test_invented_values_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client(monkeypatch, narrative("The tunnel uses 3DES and DH14, so it scores 80/100."))
    result, note = llm.generate(FACTS)
    assert result is None
    assert "3DES" in note and "DH14" in note


@pytest.mark.parametrize("text, stop_reason, expected", [
    ("{}", "refusal", "declined"),
    ("{\"executive_summary\": ", "max_tokens", "truncated"),
    ("not json", "end_turn", "invalid JSON"),
])
def test_unusable_responses_fall_back(monkeypatch: pytest.MonkeyPatch, text: str, stop_reason: str, expected: str) -> None:
    fake_client(monkeypatch, text, stop_reason)
    result, note = llm.generate(FACTS)
    assert result is None and expected in note
