"""Rekey inference: child/IKE SA rekey intervals and PFS from CREATE_CHILD_SA sizes."""
from pathlib import Path

import pytest

from app.packet.parser import analyze_pcap
from app.packet.tshark import TSharkService
from pcap_builder import esp, ikev2_encrypted, ikev2_sa_init, non_esp_marker, udp, v4, write_pcap

pytestmark = pytest.mark.skipif(not TSharkService().capabilities().available, reason="TShark is not installed")
A, B = "10.0.0.1", "10.0.0.2"
# AES-256-GCM-16 IKE SA: SK body = IV 8 + ciphertext (plaintext + pad-length byte) + ICV 16.
NO_PFS_SK = 8 + 133 + 16       # ~132-byte child rekey (SA, Nonce, TSi/TSr, N(REKEY_SA))
PFS_DH14_SK = 8 + 405 + 16     # the same plus a DH14 KE payload (8 + 256) and a DH transform (8)


def session(tmp_path: Path, rekey_sk: int) -> dict:
    frames = [
        v4(A, B, 17, udp(500, 500, ikev2_sa_init()), 0.0),
        v4(B, A, 17, udp(500, 500, ikev2_sa_init(responder=True)), 0.05),
        v4(A, B, 17, udp(4500, 4500, non_esp_marker(ikev2_encrypted(35, 1))), 0.1),
    ]
    spis = [0x100, 0x200, 0x300]
    for generation, spi in enumerate(spis):  # a child rekey every 20 s creates the next SPI
        start = 1.0 + generation * 20
        if generation:
            frames.append(v4(A, B, 17, udp(4500, 4500, non_esp_marker(ikev2_encrypted(36, 1 + generation, rekey_sk))), start - 0.5))
        frames += [v4(A, B, 50, esp(spi, n), start + n * 0.5) for n in range(1, 30)]
    # An IKE SA rekey at 45 s: CREATE_CHILD_SA with no new ESP SPIs after it.
    frames.append(v4(A, B, 17, udp(4500, 4500, non_esp_marker(ikev2_encrypted(36, 9, 300))), 45.0))
    frames.sort(key=lambda frame: frame.timestamp)
    return analyze_pcap(write_pcap(tmp_path / "rekey.pcap", frames))["features"]


def test_child_rekeys_give_interval_and_pfs(tmp_path: Path) -> None:
    features = session(tmp_path, PFS_DH14_SK)
    assert features["rekeys"] == {"child_rekeys": 2, "ike_rekeys": 1}
    interval = features["sa"]["child_rekey_interval_seconds"]
    assert interval["source"] == "inferred" and interval["value"] == pytest.approx(20, abs=1)
    assert features["sa"]["ike_rekey_interval_seconds"]["value"] == pytest.approx(45, abs=1)
    assert features["cryptography"]["pfs"] == {**features["cryptography"]["pfs"], "value": True, "source": "inferred"}


def test_small_child_rekeys_mean_no_pfs(tmp_path: Path) -> None:
    pfs = session(tmp_path, NO_PFS_SK)["cryptography"]["pfs"]
    assert pfs["value"] is False and pfs["source"] == "inferred"


def test_no_rekey_leaves_values_unobservable(tmp_path: Path) -> None:
    frames = [v4(A, B, 17, udp(500, 500, ikev2_sa_init()), 0.0), v4(B, A, 17, udp(500, 500, ikev2_sa_init(responder=True)), 0.05),
              *(v4(A, B, 50, esp(0x100, n), 1.0 + n) for n in range(1, 25))]
    features = analyze_pcap(write_pcap(tmp_path / "plain.pcap", frames))["features"]
    assert features["cryptography"]["pfs"]["source"] == "unavailable"
    assert "No CREATE_CHILD_SA" in features["sa"]["child_rekey_interval_seconds"]["evidence"][0]
