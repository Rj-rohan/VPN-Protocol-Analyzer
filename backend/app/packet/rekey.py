"""IKEv2 rekey analysis: SA rekey intervals and PFS, inferred from encrypted CREATE_CHILD_SA exchanges.

IKEv2 never sends lifetimes and encrypts PFS negotiation, but rekeys leak both:

* A CREATE_CHILD_SA request followed within seconds by new ESP SPIs is a child SA rekey;
  one without new SPIs is an IKE SA rekey. The spacing between rekeys is the rekey interval.
* With PFS, a child rekey request carries a KE payload whose size is fixed by the DH group
  (seen in cleartext IKE_SA_INIT). The encrypted message length therefore shows whether it is there.

All results are labelled `inferred` and explain their evidence.
"""
from __future__ import annotations

import re
from statistics import median

from app.packet.ike import IkeMessage
from app.packet.observations import INFERRED, observation, unavailable
from app.packet.tshark import PacketRecord

# Key exchange data length in bytes per DH group (RFC 7296 / RFC 5903 / RFC 8031).
KE_BYTES = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024, 19: 64, 20: 96, 21: 132, 22: 128, 23: 256,
            24: 256, 25: 48, 26: 56, 27: 56, 28: 64, 29: 96, 30: 128, 31: 32, 32: 56}
ICV_BYTES = {"HMAC-SHA1-96": 12, "AES-XCBC-96": 12, "HMAC-SHA2-256-128": 16, "HMAC-SHA2-384-192": 24, "HMAC-SHA2-512-256": 32}
IKE_HEADER, SK_HEADER = 28, 4
# Plaintext of a child rekey request without PFS: SA (~36-60) + Nonce (~36) + TSi/TSr (~48-96) + N(REKEY_SA) (12).
NO_PFS_BASELINE = 150
NEW_SPI_WINDOW = 5.0
CREATE_CHILD_SA = 36


def _sk_layout(encryption: str, integrity: str) -> tuple[int, int, int] | None:
    """(IV, ICV, padding block) of the IKE SA's encrypted payload, from observed IKE transforms."""
    if "GCM" in encryption or "CCM" in encryption:
        return 8, 16 if encryption.endswith("-16") else (12 if encryption.endswith("-12") else 8), 1
    if "CBC" in encryption and integrity in ICV_BYTES:
        block = 8 if "3DES" in encryption or "DES" in encryption else 16
        return block, ICV_BYTES[integrity], block
    return None


def analyze_rekeys(messages: list[IkeMessage], packets: list[PacketRecord], encryption: object, integrity: object, dh_group: object) -> dict:
    exchanges = sorted((m for m in messages if m.version == "IKEv2" and m.exchange_type == CREATE_CHILD_SA and m.timestamp and m.is_response is False),
                       key=lambda m: m.timestamp)
    first_seen: dict[str, float] = {}
    for packet in packets:
        if packet.esp_spi and packet.timestamp is not None:
            first_seen[packet.esp_spi] = min(first_seen.get(packet.esp_spi, packet.timestamp), packet.timestamp)
    spi_births = sorted(first_seen.values())
    if not exchanges:
        return {"child_rekeys": 0, "ike_rekeys": 0, "reason": "No CREATE_CHILD_SA exchange in the capture (no rekey happened while recording)"}

    child_times, ike_times, child_sizes = [], [], []
    for message in exchanges:
        if any(message.timestamp < born <= message.timestamp + NEW_SPI_WINDOW for born in spi_births):
            child_times.append(message.timestamp)
            if message.length:
                child_sizes.append(message.length)
        else:
            ike_times.append(message.timestamp)

    result: dict = {"child_rekeys": len(child_times), "ike_rekeys": len(ike_times)}
    initial_child = spi_births[0] if spi_births else None
    sa_init = min((m.timestamp for m in messages if m.version == "IKEv2" and m.exchange_type == 34 and m.timestamp), default=None)
    for name, times, start in (("child", child_times, initial_child), ("ike", ike_times, sa_init)):
        points = ([start] if start is not None else []) + times
        gaps = [b - a for a, b in zip(points, points[1:]) if b > a]
        if gaps:
            result[f"{name}_interval"] = observation(round(median(gaps)), INFERRED, [
                f"{len(times)} {'child SA' if name == 'child' else 'IKE SA'} rekey(s); median spacing {median(gaps):.0f} s "
                f"(range {min(gaps):.0f}-{max(gaps):.0f} s)",
                "New ESP SPIs followed each child rekey" if name == "child" else "No new ESP SPIs followed these CREATE_CHILD_SA exchanges",
            ])
    result["pfs"] = _pfs_from_sizes(child_sizes, str(encryption), str(integrity), str(dh_group))
    return result


def _pfs_from_sizes(sizes: list[int], encryption: str, integrity: str, dh_group: str) -> dict | None:
    if not sizes:
        return None
    layout = _sk_layout(encryption, integrity)
    group = re.search(r"DH(\d+)", dh_group)
    if layout is None or not group or int(group.group(1)) not in KE_BYTES:
        return unavailable(f"{len(sizes)} child rekey(s) seen, but the IKE SA cipher or DH group needed to size them is not observable")
    iv, icv, block = layout
    ke = KE_BYTES[int(group.group(1))]
    plaintexts = [size - IKE_HEADER - SK_HEADER - iv - icv - 1 - (block - 1) / 2 for size in sizes]
    threshold = NO_PFS_BASELINE + (ke + 16) / 2  # halfway to baseline + KE payload (8-byte header + data) + DH transform (8)
    with_ke = [p for p in plaintexts if p > threshold]
    evidence = [f"Child rekey requests carry about {min(plaintexts):.0f}-{max(plaintexts):.0f} bytes of encrypted payload; "
                f"a {dh_group} key exchange adds {ke + 8} bytes (decision threshold {threshold:.0f})"]
    if len(with_ke) == len(plaintexts):
        return observation(True, INFERRED, [*evidence, "Every child rekey is large enough to include a KE payload, so PFS is in use"])
    if not with_ke:
        return observation(False, INFERRED, [*evidence, "No child rekey is large enough to include a KE payload, so PFS is not in use"])
    return unavailable(*evidence, "Child rekey sizes are mixed; PFS cannot be decided")
