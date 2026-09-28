"""Integration tests: generated pcaps -> real TShark -> parser -> rule engine."""
import struct
from pathlib import Path

import pytest

from app.core.exceptions import AnalyzerError
from app.packet.features import UNKNOWN
from app.packet.parser import analyze_pcap
from app.packet.tshark import TSharkService
from pcap_builder import (
    esp, ikev1_main_mode, ikev2_encrypted, ikev2_sa_init, ipv4, non_esp_marker, udp, v4, v6, write_pcap,
)

pytestmark = pytest.mark.skipif(not TSharkService().capabilities().available, reason="TShark is not installed")

A, B = "10.0.0.1", "10.0.0.2"


def run(tmp_path: Path, frames) -> dict:
    return analyze_pcap(write_pcap(tmp_path / "capture.pcap", frames))


def rule_ids(result: dict) -> set[str]:
    return {finding["rule_id"] for finding in result["security"]["findings"]}


def test_ikev2_negotiation_with_nat_traversal(tmp_path: Path) -> None:
    frames = [
        v4(A, B, 17, udp(500, 500, ikev2_sa_init(nat_detection=True)), 1.0),
        v4(B, A, 17, udp(500, 500, ikev2_sa_init(nat_detection=True, responder=True)), 1.05),
        v4(A, B, 17, udp(4500, 4500, non_esp_marker(ikev2_encrypted())), 1.1),
        *(v4(A, B, 17, udp(4500, 4500, esp(0xC0FFEE01, seq)), 2.0 + seq / 10) for seq in range(1, 6)),
    ]
    result = run(tmp_path, frames)
    features = result["features"]

    assert features["detection"]["ipsec_detected"] is True
    assert features["detection"]["ike_version"] == "IKEv2"
    assert 0 < features["detection"]["confidence"] < 1
    assert features["protocol"]["ike_version"] == {"value": "IKEv2", "source": "observed", "evidence": ["3 message(s) carry an IKEv2 header (ISAKMP version 2.0)"]}
    assert "IKE_SA_INIT" in features["protocol"]["ike_exchange_types"]["value"]
    crypto = features["cryptography"]
    assert crypto["encryption_algorithm"]["value"] == "AES-256-GCM-16"
    assert crypto["encryption_algorithm"]["source"] == "observed"
    assert crypto["integrity_algorithm"]["value"] == "AEAD"
    assert crypto["prf_algorithm"]["value"] == "HMAC-SHA2-256"
    assert crypto["dh_group"]["value"] == "DH14 (MODP-2048)"
    assert crypto["authentication_method"]["value"] == UNKNOWN  # carried in encrypted IKE_AUTH
    assert crypto["pfs"]["value"] == UNKNOWN
    assert features["sa"]["nat_traversal"]["value"] is True
    assert features["sa"]["sa_lifetime_seconds"]["value"] == UNKNOWN
    assert features["mode"]["value"] == "Unknown"  # encrypted ESP must not be forced into a mode
    assert features["protocol"]["ip_version"]["value"] == "IPv4"
    assert "PROTO-001" not in rule_ids(result)
    assert "CRYPTO-001" not in rule_ids(result)


def test_ikev1_main_mode_legacy_configuration(tmp_path: Path) -> None:
    frames = [
        v4(A, B, 17, udp(500, 500, ikev1_main_mode()), 1.0),
        v4(B, A, 17, udp(500, 500, ikev1_main_mode(responder=True)), 1.1),
        *(v4(A, B, 50, esp(0x1000, seq), 2.0 + seq) for seq in range(1, 4)),
    ]
    result = run(tmp_path, frames)
    features = result["features"]
    crypto = features["cryptography"]

    assert features["protocol"]["ike_version"]["value"] == "IKEv1"
    assert "Main Mode (Identity Protection)" in features["protocol"]["ike_exchange_types"]["value"]
    assert crypto["encryption_algorithm"]["value"] == "AES-256-CBC"
    assert crypto["integrity_algorithm"]["value"] == "HMAC-SHA1"
    assert crypto["authentication_method"]["value"] == "Pre-Shared Key"
    assert crypto["dh_group"]["value"] == "DH2 (MODP-1024)"
    assert features["sa"]["sa_lifetime_seconds"]["value"] == 86400
    assert features["sa"]["nat_traversal"] == {
        "value": False, "source": "observed",
        "evidence": ["3 ESP packet(s) are carried directly as IP protocol 50 without UDP encapsulation"],
    }
    assert {"PROTO-001", "CRYPTO-001", "CRYPTO-002"} <= rule_ids(result)


def test_initiator_offer_without_reply_is_not_treated_as_negotiated(tmp_path: Path) -> None:
    offer = ikev2_sa_init(encryption=((12, 256), (12, 128)), integ=12)
    features = run(tmp_path, [v4(A, B, 17, udp(500, 500, offer), 1.0)])["features"]

    encryption = features["cryptography"]["encryption_algorithm"]
    assert encryption["value"] == UNKNOWN
    assert "AES-128-CBC, AES-256-CBC" in encryption["evidence"][0]
    # A single offered value is labelled inferred, not observed.
    assert features["cryptography"]["dh_group"]["source"] == "inferred"


def test_esp_null_exposes_tunnel_mode(tmp_path: Path) -> None:
    inner = ipv4("192.168.1.10", "192.168.2.20", 1, b"\x08\x00\xf7\xff\x00\x01\x00\x01" + b"x" * 24)
    frames = [
        v4(A, B, 50, struct.pack("!II", 0xABC, seq) + inner + bytes([1, 2, 2, 4]) + b"\x00" * 12, 1.0 + seq)
        for seq in range(1, 4)
    ]
    mode = run(tmp_path, frames)["features"]["mode"]

    assert mode["value"] == "Tunnel"
    assert mode["source"] == "inferred"
    assert mode["confidence"] == 0.9


def test_esp_null_is_flagged_as_unencrypted(tmp_path: Path) -> None:
    inner = ipv4("192.168.1.10", "192.168.2.20", 1, b"\x08\x00\xf7\xff\x00\x01\x00\x01" + b"x" * 24)
    frames = [v4(A, B, 50, struct.pack("!II", 0xABC, seq) + inner + bytes([1, 2, 2, 4]) + b"\x00" * 12, 1.0 + seq) for seq in range(1, 4)]
    result = run(tmp_path, frames)

    assert result["features"]["sa"]["payload_confidentiality"]["value"] is False
    assert "CRYPTO-005" in rule_ids(result)
    assert result["security"]["assessment"]["risk_level"] == "Critical"


def test_esp_null_transport_mode_exposes_endpoints(tmp_path: Path) -> None:
    udp_payload = udp(5004, 5004, b"v" * 40)
    frames = [v4(A, B, 50, struct.pack("!II", 0xDEF, seq) + udp_payload + bytes([1, 2, 2, 17]) + b"\x00" * 12, 1.0 + seq) for seq in range(1, 4)]
    result = run(tmp_path, frames)

    assert result["features"]["mode"]["value"] == "Transport"
    assert {"META-001", "CRYPTO-005"} <= rule_ids(result)


def test_traffic_metadata_direction_and_bursts(tmp_path: Path) -> None:
    frames = [v4(A, B, 17, udp(500, 500, ikev2_sa_init()), 0.5)]
    # Three bursts of four uplink packets (1 ms apart), each answered by one larger downlink packet.
    for burst in range(3):
        start = 1.0 + burst
        frames += [v4(A, B, 50, esp(0x10, burst * 4 + n + 1, size=100), start + n * 0.001) for n in range(4)]
        frames.append(v4(B, A, 50, esp(0x20, burst + 1, size=900), start + 0.5))
    traffic = run(tmp_path, frames)["features"]["traffic"]
    f = traffic["features"]

    assert f["flow_packet_count"] == 15
    assert (f["packets_up"], f["packets_down"]) == (12, 3)
    assert f["bytes_up"] < f["bytes_down"] * 4 and 0 < f["uplink_ratio"] < 1
    assert f["max_burst_packets"] == 4
    assert f["direction_changes"] == 5
    assert "IKE initiator" in traffic["direction_basis"]
    assert sum(bucket["packets"] for bucket in traffic["size_histogram"]) == 15
    assert traffic["timeline"][0]["packets"] > 0


def test_ipv6_esp_and_replay_indicators(tmp_path: Path) -> None:
    frames = [v6(1, 2, 50, esp(0x2002, seq), 1.0 + index) for index, seq in enumerate((1, 2, 2, 3))]
    features = run(tmp_path, frames)["features"]

    assert features["protocol"]["ip_version"]["value"] == "IPv6"
    assert features["replay_indicators"]["duplicate_sequence_numbers"] == 1
    # Sender sequence numbers do not prove the receiver enforces anti-replay.
    assert features["sa"]["replay_protection"]["value"] == UNKNOWN


def test_ike_only_capture_does_not_claim_replay_protection(tmp_path: Path) -> None:
    features = run(tmp_path, [v4(A, B, 17, udp(500, 500, ikev2_sa_init()), 1.0)])["features"]

    assert features["sa"]["replay_protection"]["value"] == UNKNOWN
    assert features["detection"]["esp_detected"] is False


def test_non_pcap_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "fake.pcap"
    path.write_bytes(b"this is not a capture file")
    with pytest.raises(AnalyzerError):
        analyze_pcap(path)


def test_truncated_capture_returns_readable_packets_with_warning(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "cut.pcap", [v4(A, B, 50, esp(0x1, seq), 1.0 + seq) for seq in range(1, 4)])
    path.write_bytes(path.read_bytes()[:-20])
    result = analyze_pcap(path)

    assert result["packet_count"] == 2
    assert result["warnings"]


def test_ah_decoded_inside_esp_is_ignored() -> None:
    """Real phone capture: the ESP-NULL heuristic decoded encrypted bytes as `esp:ah:ax25`."""
    columns = [("frame_number", "frame.number"), ("protocols", "frame.protocols"), ("esp_spi", "esp.spi"),
               ("ah_spi", "ah.spi"), ("ah_sequence", "ah.sequence")]
    noise = TSharkService._record("4798\teth:ethertype:ip:udp:udpencap:esp:ah:ax25\t0xc1a339a4\t0x3130f73a\t7", columns)
    assert noise.esp_spi == "0xc1a339a4" and noise.ah_spi is None and noise.ah_sequence is None
    real_ah = TSharkService._record("12\teth:ethertype:ip:ah:icmp\t\t0xc2000001\t5", columns)
    assert real_ah.ah_spi == "0xc2000001" and real_ah.ah_sequence == 5
