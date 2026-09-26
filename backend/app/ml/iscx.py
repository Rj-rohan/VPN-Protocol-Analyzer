"""Import the ISCX VPN-nonVPN 2016 dataset as traffic-classification features.

    python -m app.ml.iscx                                  # data/raw/iscx2016 -> data/processed/iscx_features.csv
    python -m app.ml.iscx --source D:\\iscx --window 15

The VPN captures were recorded on the OpenVPN client's tunnel interface (raw IP,
client addresses in 10.8.0.0/16): they hold the applications' inner packets, not
encrypted OpenVPN datagrams. For each `vpn_*` capture this importer:

1. labels it from the filename (P2P/BitTorrent and unrecognised files are skipped);
2. keeps every packet to or from the VPN client (the busiest private address);
3. wraps each inner IP packet as tunnel-mode ESP (AES-GCM) and uses that on-the-wire
   size, keeping the real timestamp and direction;
4. cuts the capture into fixed windows and computes the analyzer's traffic features.

Rows are labelled `dataset_origin = iscx_vpn_2016_openvpn_converted` and grouped by
source file, so windows of one recording never end up on both sides of a split.

Citation: G. Draper-Gil, A. H. Lashkari, M. Mamun, A. A. Ghorbani, "Characterization
of Encrypted and VPN Traffic Using Time-Related Features", ICISSP 2016, pp. 407-414.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path

import pandas as pd

from app.config import REPO_DIR
from app.ml.features import from_traffic_metadata
from app.ml.preprocessing import GROUP, LABEL

DEFAULT_SOURCE = REPO_DIR / "data" / "raw" / "iscx2016"
DEFAULT_OUTPUT = REPO_DIR / "data" / "processed" / "iscx_features.csv"
ORIGIN = "iscx_vpn_2016_openvpn_converted"
ORIGIN_NONVPN = "iscx_nonvpn_2016_esp_converted"  # same apps recorded without a VPN, wrapped as ESP the same way

# Tunnel-mode ESP with AES-GCM-16 around an inner IP packet: Ethernet 14 + outer IPv4 20 +
# ESP header 8 + IV 8 + trailer (pad length, next header) 2 + ICV 16; ESP payload padded to 4 bytes.
ESP_FIXED = 14 + 20 + 8 + 8 + 2 + 16

# Checked in order: the first matching pattern decides the class.
LABEL_RULES: list[tuple[str, str | None]] = [
    (r"torrent|bittorrent|p2p", None),                 # no SIH class for peer-to-peer
    (r"chat", "Chat"),                                  # before email: gmailchat is chat
    (r"audio|voipbuster|voip", "VoIP"),
    (r"video|youtube|vimeo|netflix|spotify|stream", "Video"),
    (r"email|mail|smtp|pop3|imap", "Email"),
    (r"ftps|sftp|scp|file|ftp", "File-Transfer"),
    (r"brows|http|web", "Web"),
]


def label_for(filename: str) -> str | None:
    name = filename.lower()
    for pattern, label in LABEL_RULES:
        if re.search(pattern, name):
            return label
    return None


def esp_size(inner_ip_length: int) -> int:
    """On-the-wire frame size of an inner IP packet carried in tunnel-mode ESP (AES-GCM-16)."""
    inner = max(20, inner_ip_length)
    return ESP_FIXED + inner + (-(inner + 2) % 4)


_CLIENT_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def _private(address: str | None) -> bool:
    """RFC 1918 / ULA addresses only (Python's is_private also matches documentation ranges)."""
    try:
        ip = ipaddress.ip_address(address) if address else None
    except ValueError:
        return False
    return ip is not None and any(ip in network for network in _CLIENT_NETWORKS if network.version == ip.version)


def _unicast(address: str | None) -> bool:
    try:
        ip = ipaddress.ip_address(address) if address else None
    except ValueError:
        return False
    return ip is not None and not (ip.is_multicast or ip.is_unspecified or str(ip).endswith(".255"))


def client_packets(packets: list) -> tuple[list, dict]:
    """Keep every packet of the recording host and rewrite it as the ESP packet a tunnel would carry.

    VPN captures: the host is the OpenVPN client (a private 10.8.x.x address). Non-VPN captures:
    the host is whichever unicast address takes part in the most packets.
    """
    private = Counter(a for p in packets for a in (p.src, p.dst) if _private(a))
    anyone = Counter(a for p in packets for a in (p.src, p.dst) if _unicast(a))
    if not anyone:
        return [], {"reason": "no IP traffic"}
    top_private = private.most_common(1)[0] if private else None
    top_any = anyone.most_common(1)[0]
    # Prefer the private client unless another host clearly dominates (non-VPN captures on public addresses).
    client = top_private[0] if top_private and top_private[1] >= 0.5 * top_any[1] else top_any[0]
    members = [p for p in packets if client in (p.src, p.dst) and p.timestamp is not None]
    converted = [
        replace(p, length=esp_size(p.ip_total_length or p.length), protocols=["eth", "ip", "esp"],
                ip_src=p.src, ip_dst=p.dst, esp_spi="0x1c5c0001" if p.src == client else "0x1c5c0002",
                esp_sequence=None, udp_srcport=None, udp_dstport=None)
        for p in members
    ]
    return converted, {"client": client, "packet_share": round(len(members) / len(packets), 3), "packets": len(members)}


def windows(records: list, seconds: float, min_packets: int, max_windows: int) -> list[list]:
    if not records:
        return []
    start = records[0].timestamp
    buckets: dict[int, list] = defaultdict(list)
    for record in records:
        buckets[int((record.timestamp - start) // seconds)].append(record)
    chosen = [bucket for _, bucket in sorted(buckets.items()) if len(bucket) >= min_packets]
    if len(chosen) > max_windows:
        step = len(chosen) / max_windows
        chosen = [chosen[int(i * step)] for i in range(max_windows)]
    return chosen


def process_file(path: str, seconds: float, min_packets: int, max_windows: int) -> tuple[list[dict], str]:
    from app.packet.traffic import extract_traffic_metadata
    from app.packet.tshark import TSharkService

    pcap = Path(path)
    label = label_for(pcap.stem)
    packets = TSharkService(timeout=3600).packet_records(pcap)
    records, info = client_packets(packets)
    if not records:
        return [], f"{pcap.name}: skipped ({info.get('reason')})"
    rows = []
    for index, window in enumerate(windows(records, seconds, min_packets, max_windows)):
        features = from_traffic_metadata(extract_traffic_metadata(window, [])["features"])
        origin = ORIGIN if pcap.name.lower().startswith("vpn") else ORIGIN_NONVPN
        rows.append({**features, LABEL: label, GROUP: f"iscx:{pcap.stem}", "session_id": f"iscx_{pcap.stem}_w{index:03d}",
                     "dataset_origin": origin, "source_file": pcap.name})
    return rows, (f"{pcap.name}: {label}, {len(rows)} window(s) from {info['packets']:,} client packets "
                  f"({info['packet_share']:.0%} of the capture), client {info['client']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="folder containing the extracted ISCX captures")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--window", type=float, default=15.0, help="window length in seconds (lab sessions last 8-20 s)")
    parser.add_argument("--min-packets", type=int, default=5, help="windows with fewer packets are dropped (email and chat are sparse)")
    parser.add_argument("--max-windows", type=int, default=40, help="per capture, so long recordings do not dominate")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--include-nonvpn", action="store_true",
                        help="also import the non-VPN captures: the same real apps, many more recordings per class, wrapped as ESP the same way")
    args = parser.parse_args()

    files = sorted(p for p in args.source.rglob("*") if p.suffix.lower() in (".pcap", ".pcapng"))
    if not args.include_nonvpn:
        files = [p for p in files if p.name.lower().startswith("vpn")]
    usable, skipped = [], []
    for path in files:
        (usable if label_for(path.stem) else skipped).append(path)
    if not usable:
        raise SystemExit(f"No labelled VPN captures under {args.source}. Extract the ISCX VPN-PCAPS archives there first.")
    print(f"{len(usable)} capture(s) to import; skipped by label: {', '.join(p.name for p in skipped) or 'none'}", flush=True)

    rows: list[dict] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(process_file, str(p), args.window, args.min_packets, args.max_windows) for p in usable]
        for future in as_completed(futures):
            try:
                file_rows, message = future.result()
            except Exception as exc:  # one damaged capture should not stop the import
                message = f"FAILED: {exc}"
                file_rows = []
            rows += file_rows
            print(f"  {message}", flush=True)

    frame = pd.DataFrame(rows)
    if frame.empty:
        raise SystemExit("No windows extracted.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, index=False)
    counts = frame.groupby(LABEL).agg(windows=(LABEL, "size"), captures=(GROUP, "nunique"))
    print(f"\nWrote {len(frame)} windows from {frame[GROUP].nunique()} captures to {args.output}\n{counts.to_string()}")


if __name__ == "__main__":
    main()
