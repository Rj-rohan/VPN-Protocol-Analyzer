"""Build small, protocol-correct pcap files for parser integration tests.

The packets follow RFC 7296 (IKEv2), RFC 2408/2409 (IKEv1) and RFC 4303 (ESP)
wire formats so TShark dissects them exactly as it would real traffic.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

ETH_IPV4 = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
ETH_IPV6 = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x86\xdd"


@dataclass
class Frame:
    data: bytes
    timestamp: float


def _checksum(header: bytes) -> int:
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
        bytes(int(part) for part in src.split(".")), bytes(int(part) for part in dst.split(".")),
    )
    return header[:10] + struct.pack("!H", _checksum(header)) + header[12:] + payload


def ipv6(src_last: int, dst_last: int, next_header: int, payload: bytes) -> bytes:
    prefix = bytes.fromhex("20010db8000000000000000000000000")[:15]
    return struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64) + prefix + bytes([src_last]) + prefix + bytes([dst_last]) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def esp(spi: int, sequence: int, next_header: int = 4, size: int = 64) -> bytes:
    # Encrypted body is opaque; the trailing next-header byte is only readable for ESP-NULL.
    return struct.pack("!II", spi, sequence) + b"\xa5" * size + bytes([0, next_header])


# --- IKEv2 (RFC 7296) -------------------------------------------------------

def _ikev2_transform(ttype: int, tid: int, key_length: int | None = None, last: bool = False) -> bytes:
    attrs = struct.pack("!HH", 0x800E, key_length) if key_length else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def ikev2_sa_init(
    encryption: tuple[tuple[int, int | None], ...] = ((20, 256),), prf: int = 5, integ: int | None = None, dh: int = 14,
    nat_detection: bool = False, responder: bool = False,
) -> bytes:
    """IKE_SA_INIT with one proposal; several `encryption` entries are offered as alternatives."""
    transforms = [(1, encr, key_length) for encr, key_length in encryption] + [(2, prf, None)]
    if integ is not None:
        transforms.append((3, integ, None))
    transforms.append((4, dh, None))
    body = b"".join(_ikev2_transform(t, i, k, last=n == len(transforms) - 1) for n, (t, i, k) in enumerate(transforms))
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(body), 1, 1, 0, len(transforms)) + body
    ke_data = struct.pack("!HH", dh, 0) + b"\x42" * 32
    nonce = b"\x17" * 32
    notifies = []
    if nat_detection:
        notifies = [struct.pack("!BBH", 0, 0, 16388) + b"\x01" * 20, struct.pack("!BBH", 0, 0, 16389) + b"\x02" * 20]
    payloads = [(33, proposal), (34, ke_data), (40, nonce)] + [(41, n) for n in notifies]
    encoded = b""
    for index, (_, data) in enumerate(payloads):
        next_type = payloads[index + 1][0] if index + 1 < len(payloads) else 0
        encoded += struct.pack("!BBH", next_type, 0, 4 + len(data)) + data
    spi_r = b"\x22" * 8 if responder else b"\x00" * 8
    header = b"\x11" * 8 + spi_r + struct.pack("!BBBBII", 33, 0x20, 34, 0x20 if responder else 0x08, 0, 28 + len(encoded))
    return header + encoded


def ikev2_encrypted(exchange: int = 35, message_id: int = 1, sk_body: int = 64) -> bytes:
    """An IKE_AUTH / CREATE_CHILD_SA request whose payloads sit inside an SK payload of `sk_body` bytes (IV + ciphertext + ICV)."""
    sk = struct.pack("!BBH", 35, 0, 4 + sk_body) + b"\x5a" * sk_body
    return b"\x11" * 8 + b"\x22" * 8 + struct.pack("!BBBBII", 46, 0x20, exchange, 0x08, message_id, 28 + len(sk)) + sk


# --- IKEv1 (RFC 2408 / 2409) ------------------------------------------------

def _tv(attr: int, value: int) -> bytes:
    return struct.pack("!HH", 0x8000 | attr, value)


def _tlv(attr: int, value: int) -> bytes:
    return struct.pack("!HHI", attr, 4, value)


def non_esp_marker(ike_message: bytes) -> bytes:
    """IKE over UDP 4500 is prefixed with four zero bytes (RFC 3948)."""
    return b"\x00\x00\x00\x00" + ike_message


def ikev1_main_mode(
    encryption: int = 7, key_length: int | None = 256, hash_alg: int = 2, auth: int = 1, group: int = 2,
    lifetime: int = 86400, responder: bool = False,
) -> bytes:
    attrs = _tv(1, encryption) + (_tv(14, key_length) if key_length else b"") + _tv(2, hash_alg) + _tv(3, auth) + _tv(4, group) + _tv(11, 1)
    attrs += _tv(12, lifetime) if lifetime < 0x10000 else _tlv(12, lifetime)
    transform = struct.pack("!BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa = struct.pack("!BBHII", 0, 0, 12 + len(proposal), 1, 1) + proposal
    responder_cookie = b"\x44" * 8 if responder else b"\x00" * 8
    return b"\x33" * 8 + responder_cookie + struct.pack("!BBBBII", 1, 0x10, 2, 0, 0, 28 + len(sa)) + sa


# --- pcap writer -----------------------------------------------------------

def write_pcap(path: Path, frames: list[Frame]) -> Path:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for frame in frames:
            seconds = int(frame.timestamp)
            micros = int(round((frame.timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, micros, len(frame.data), len(frame.data)) + frame.data)
    return path


def v4(src: str, dst: str, proto: int, payload: bytes, timestamp: float) -> Frame:
    return Frame(ETH_IPV4 + ipv4(src, dst, proto, payload), timestamp)


def v6(src_last: int, dst_last: int, next_header: int, payload: bytes, timestamp: float) -> Frame:
    return Frame(ETH_IPV6 + ipv6(src_last, dst_last, next_header, payload), timestamp)
