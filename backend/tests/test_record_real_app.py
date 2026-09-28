import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "testbed" / "scripts" / "record_real_app.py"
spec = importlib.util.spec_from_file_location("record_real_app", SCRIPT)
recorder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recorder)

# `swanctl --list-sas` from a phone (Android built-in IKEv2 client) behind Docker's NAT.
ANDROID_SAS = """phones: #1, ESTABLISHED, IKEv2, 7a1c2f3e4d5b6a79_i 1f2e3d4c5b6a7980_r*
  local  '192.168.1.5' @ 172.19.0.2[4500]
  remote 'phone' @ 172.19.0.1[4500] [10.10.10.1]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  established 42s ago, rekeying in 13800s
  internet: #1, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_GCM_16-256
    installed 42s ago, rekeying in 3300s, expires in 3900s
    in  c7d1e2f3,  51234 bytes,   310 packets,     0s ago
    out 0a1b2c3d, 812345 bytes,   702 packets,     0s ago
    local  0.0.0.0/0
    remote 10.10.10.1/32
"""


def test_parse_sas_reads_phone_and_negotiated_settings() -> None:
    sas = recorder.parse_sas(ANDROID_SAS)
    assert sas["established"] and sas["installed"]
    assert sas["ike_proposal"] == "AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048"
    assert sas["esp"] == "AES_GCM_16-256" and sas["mode"] == "Tunnel" and sas["nat_traversal"] is True
    assert sas["phone_id"] == "phone" and sas["phone_virtual_ip"] == "10.10.10.1"


def test_parse_sas_reads_how_much_data_arrived() -> None:
    sas = recorder.parse_sas(ANDROID_SAS)
    assert sas["packets_in"] == 310 and sas["bytes_in"] == 51234
    # The Windows failure mode: IKE up, but no ESP data ever reaches the server.
    stuck = recorder.parse_sas(ANDROID_SAS.replace("51234 bytes,   310 packets", "0 bytes,     0 packets"))
    assert stuck["packets_in"] == 0


def test_local_mode_ignores_virtualbox_nat_and_container_bridges(monkeypatch) -> None:
    listing = ("2: enp0s3    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3\\n"
               "3: enp0s8    inet 10.44.13.52/24 brd 10.44.13.255 scope global dynamic enp0s8\\n"
               "4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\n").replace("\\n", "\n")
    monkeypatch.setattr(recorder.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": listing})())
    assert recorder.LocalServer.candidate_addresses() == [("enp0s8", "10.44.13.52")]


def test_parse_sas_without_a_phone() -> None:
    sas = recorder.parse_sas("")
    assert not sas["established"] and not sas["installed"]


def test_negotiated_esp_maps_to_proposal_keywords() -> None:
    assert recorder.to_proposal("AES_GCM_16-256") == "aes256gcm16"
    assert recorder.to_proposal("AES_GCM_16-128/ECP_256") == "aes128gcm16-ecp256"
    assert recorder.to_proposal("AES_CBC-256/HMAC_SHA2_256_128/MODP_2048") == "aes256-sha256-modp2048"
    assert recorder.to_proposal("AES_CBC-128/HMAC_SHA1_96") == "aes128-sha1"
    assert recorder.to_proposal(None) is None


def test_label_is_compatible_with_the_session_loader() -> None:
    from app.ml.protocol_models import AEAD, family_from_proposal

    label = recorder.build_label("whatsapp_voice-call_00", "whatsapp", "voice-call", "VoIP", 120.4,
                                 recorder.parse_sas(ANDROID_SAS), ANDROID_SAS)
    # The keys load_sessions() reads, and a cipher family the protocol models understand.
    assert {"session_id", "pcap_filename", "traffic", "group", "dataset_origin", "mode", "esp_proposal", "ip_version"} <= set(label)
    assert label["traffic"] == "VoIP" and label["mode"] == "Tunnel" and label["group"] == label["session_id"]
    assert family_from_proposal(label["esp_proposal"]) == AEAD
    json.dumps(label)


def test_server_config_has_pool_psk_and_full_tunnel() -> None:
    config = recorder.render("192.168.1.5", "abcdefgh23456789")
    assert "id = 192.168.1.5" in config and 'secret = "abcdefgh23456789"' in config
    assert "local_ts = 0.0.0.0/0" in config and f"addrs = {recorder.POOL}" in config
    assert config.count("{") == config.count("}")


def test_activities_map_to_the_seven_traffic_classes() -> None:
    from app.ml.features import TRAFFIC_CLASSES

    assert set(recorder.ACTIVITIES.values()) <= set(TRAFFIC_CLASSES)
    assert recorder.ACTIVITIES["voice-call"] == "VoIP" and recorder.ACTIVITIES["chat"] == "Chat"


def test_rate_profile_separates_the_activity_from_background_bursts(tmp_path) -> None:
    import struct

    frames = []
    for second in range(60):  # a steady ~6 KB/s voice call ...
        frames += [(second, 200)] * 30
    frames += [(35, 1400)] * 1000  # ... with one 1.4 MB background burst at 30-40 s
    body = b"".join(struct.pack("<IIII", t, 0, 0, length) for t, length in sorted(frames))
    pcap = tmp_path / "call.pcap"
    pcap.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + body)
    profile = recorder.rate_profile(pcap)
    assert profile["median_kbps"] == 6.0
    assert profile["bursts"] == [(30, 146.0)]
