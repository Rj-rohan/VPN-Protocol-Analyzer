"""Parser accuracy against real strongSwan captures (data/raw/testbed).

Generate the captures with `python testbed/scripts/run_testbed.py`. Each
capture_NNN.json is the ground truth for capture_NNN.pcap. Values the parser
reports as unavailable are allowed; any value it does report must match.
"""
import json
from pathlib import Path

import pytest

from app.packet.features import UNKNOWN
from app.packet.parser import analyze_pcap
from app.packet.tshark import TSharkService

TESTBED = Path(__file__).resolve().parents[2] / "data" / "raw" / "testbed"
CASES = sorted(TESTBED.glob("capture_*.json")) if TESTBED.exists() else []

pytestmark = [
    pytest.mark.skipif(not CASES, reason="No testbed captures; run testbed/scripts/run_testbed.py"),
    pytest.mark.skipif(not TSharkService().capabilities().available, reason="TShark is not installed"),
]

_cache: dict[Path, dict] = {}


def analysis(truth_path: Path) -> tuple[dict, dict]:
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    if truth_path not in _cache:
        _cache[truth_path] = analyze_pcap(TESTBED / truth["pcap_filename"])
    return truth, _cache[truth_path]


@pytest.mark.parametrize("truth_path", CASES, ids=[path.stem for path in CASES])
def test_protocol_identification(truth_path: Path) -> None:
    truth, result = analysis(truth_path)
    features = result["features"]

    if not truth.get("ipsec_expected", True):
        assert features["detection"]["ipsec_detected"] is False
        assert result["packet_count"] > 0  # normal traffic was captured and analysed
        assert result["security"]["findings"] == []  # no IPsec, so no IPsec findings
        return
    protocol = truth.get("ipsec_protocol", "ESP")
    assert features["detection"]["ipsec_detected"] is True
    assert features["detection"]["ike_detected"] is True
    assert features["detection"]["esp_detected"] is (protocol == "ESP")
    assert features["detection"]["ah_detected"] is (protocol == "AH")
    assert features["protocol"]["ipsec_protocol"] == protocol
    assert features["protocol"]["ike_version"]["value"] == truth["ike_version"]
    assert features["protocol"]["ip_version"]["value"] == truth["ip_version"]
    assert features["sa"]["nat_traversal"]["value"] == truth["nat_traversal"]


@pytest.mark.parametrize("truth_path", CASES, ids=[path.stem for path in CASES])
def test_ike_sa_cryptography(truth_path: Path) -> None:
    truth, result = analysis(truth_path)
    crypto = result["features"]["cryptography"]
    expected = truth["ike_sa"]

    for field, key in (("encryption_algorithm", "encryption"), ("integrity_algorithm", "integrity"), ("dh_group", "dh_group"), ("prf_algorithm", "prf")):
        if expected.get(key) is None:
            continue
        assert crypto[field]["value"] == expected[key], f"{field}: {crypto[field]}"
        assert crypto[field]["source"] == "observed", f"{field} should come from the responder's selection"


@pytest.mark.parametrize("truth_path", CASES, ids=[path.stem for path in CASES])
def test_reported_values_never_contradict_ground_truth(truth_path: Path) -> None:
    truth, result = analysis(truth_path)
    if not truth.get("ipsec_expected", True):
        return
    features = result["features"]

    mode = features["mode"]["value"]
    if truth["mode_observable"]:
        assert mode == truth["mode"], features["mode"]
    else:
        assert mode in ("Unknown", truth["mode"]), features["mode"]

    pfs = features["cryptography"]["pfs"]["value"]
    assert pfs in (UNKNOWN, truth["pfs"]), features["cryptography"]["pfs"]

    auth = features["cryptography"]["authentication_method"]["value"]
    assert auth in (UNKNOWN, truth["authentication"]), features["cryptography"]["authentication_method"]

    if truth.get("ipsec_protocol") == "AH":
        assert features["sa"]["payload_confidentiality"]["value"] is False  # AH authenticates but never encrypts


REKEY_CASES = [p for p in CASES if json.loads(p.read_text(encoding="utf-8")).get("child_rekey_seconds")]


@pytest.mark.skipif(not REKEY_CASES, reason="No rekey scenarios captured yet (capture_015-017)")
@pytest.mark.parametrize("truth_path", REKEY_CASES, ids=[p.stem for p in REKEY_CASES])
def test_rekey_inference(truth_path: Path) -> None:
    truth, result = analysis(truth_path)
    sa, crypto = result["features"]["sa"], result["features"]["cryptography"]

    interval = sa["child_rekey_interval_seconds"]
    assert interval["source"] == "inferred", interval
    assert abs(interval["value"] - truth["child_rekey_seconds"]) <= max(3, 0.2 * truth["child_rekey_seconds"]), interval
    assert crypto["pfs"]["value"] == truth["pfs"] and crypto["pfs"]["source"] == "inferred", crypto["pfs"]
