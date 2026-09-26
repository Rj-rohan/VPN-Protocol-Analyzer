from pathlib import Path

import pytest

from app.ml.features import FULL_FEATURES
from app.ml.iscx import ESP_FIXED, esp_size, label_for, process_file
from app.packet.tshark import TSharkService
from pcap_builder import udp, v4, write_pcap


@pytest.mark.parametrize("name, label", [
    ("vpn_skype_audio1", "VoIP"), ("vpn_voipbuster1a", "VoIP"), ("vpn_hangouts_chat1b", "Chat"), ("gmailchat1", "Chat"),
    ("vpn_email2a", "Email"), ("vpn_youtube_A", "Video"), ("vpn_netflix_A", "Video"), ("vpn_spotify_A", "Video"),
    ("vpn_sftp_B", "File-Transfer"), ("vpn_skype_files1a", "File-Transfer"), ("vpn_ftps_A", "File-Transfer"),
    ("vpn_bittorrent", None), ("mystery_capture", None),
])
def test_labels_come_from_iscx_filenames(name: str, label: str | None) -> None:
    assert label_for(name) == label


def test_inner_packets_are_sized_as_tunnel_mode_esp() -> None:
    inner = 229  # an IPv4 packet of 229 bytes
    size = esp_size(inner)
    assert size >= ESP_FIXED + inner
    assert (size - 14 - 20 - 8 - 8 - 16) % 4 == 0  # ESP payload (inner + pad + trailer) stays 4-byte aligned


@pytest.mark.skipif(not TSharkService().capabilities().available, reason="TShark is not installed")
def test_process_file_keeps_client_traffic_and_windows_it(tmp_path: Path) -> None:
    client, server = "10.8.0.10", "203.0.113.9"
    frames = []
    for n in range(600):  # 30 s of a two-way call from the VPN client, 20 packets/s
        t = 1.0 + n * 0.05
        if n % 2:
            frames.append(v4(client, server, 17, udp(50000, 3478, b"v" * 200), t))
        else:
            frames.append(v4(server, client, 17, udp(3478, 50000, b"v" * 200), t))
    frames += [v4("198.51.100.1", "198.51.100.2", 17, udp(123, 123, b"n" * 40), 1.0 + n) for n in range(5)]  # not the client
    path = write_pcap(tmp_path / "vpn_skype_audio1a.pcap", frames)

    rows, message = process_file(str(path), seconds=15, min_packets=5, max_windows=40)

    assert "VoIP" in message and "client 10.8.0.10" in message and "600 client packets" in message
    assert len(rows) == 2
    assert all(row["traffic_label"] == "VoIP" and row["group"] == "iscx:vpn_skype_audio1a" for row in rows)
    assert all(set(FULL_FEATURES) <= set(row) for row in rows)
    first = rows[0]
    assert 0.45 < first["uplink_ratio"] < 0.55  # direction follows the VPN client
    assert first["packets_per_second"] == pytest.approx(20, rel=0.1)
    assert first["avg_packet_size_bytes"] == esp_size(20 + 8 + 200)
