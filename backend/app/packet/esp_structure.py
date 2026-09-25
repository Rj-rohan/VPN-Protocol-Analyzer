"""ESP length-lattice analysis: infer the ESP cipher family and inner-packet sizes from encrypted lengths.

Every ESP packet carries IV + ciphertext + ICV after the 8-byte ESP header, and the
ciphertext is padded to the cipher's block size:

    payload = IV + ciphertext + ICV,   ciphertext = inner + pad + 2,   ciphertext % block == 0

Cipher family: Bayesian comparison of layouts. If d distinct lengths all sit on a
16-byte grid, a 4-byte-aligned AEAD layout would produce that by chance with
probability (1/4)^d, so the posterior favours the block cipher. With few distinct
lengths (e.g. constant-size VoIP) the layouts cannot be told apart and no
cipher is reported.

Mode: once the layout is known, each packet's inner size is recovered. Tunnel mode
carries a full inner IP header (20 bytes IPv4, 40 IPv6), so small packets such as
TCP ACKs are about 20-40 bytes larger than in transport mode. These cipher-independent
inner sizes are the features for the mode classifier in app.ml.protocol_models.
"""
from __future__ import annotations

import math
from collections import Counter

from app.packet.tshark import PacketRecord

# family: (IV bytes, padding block, ICV bytes)
LAYOUTS: dict[str, tuple[int, int, int]] = {
    "AEAD (AES-GCM or ChaCha20-Poly1305)": (8, 4, 16),
    "AES-CBC + HMAC-SHA1-96": (16, 16, 12),
    "AES-CBC + HMAC-SHA2-256-128": (16, 16, 16),
    "64-bit block cipher (3DES/Blowfish) + HMAC-SHA1-96": (8, 8, 12),
}
NULL_FAMILY = "NULL encryption + HMAC-SHA2-256-128"
MIN_PACKETS = 20
MIN_DISTINCT_LENGTHS = 4
MISFIT_LOG_PENALTY = math.log(1e-3)  # a distinct length off the layout's grid
BASE_GRID = 4                        # every ESP payload is at least 4-byte aligned (RFC 4303)


def _fits(length: int, iv: int, block: int, icv: int) -> bool:
    ciphertext = length - iv - icv
    return ciphertext >= 2 and ciphertext % block == 0


def cipher_posterior(lengths: list[int]) -> dict[str, float]:
    """Posterior over layouts (uniform prior); each fitting distinct length contributes log(block / 4)."""
    distinct = set(lengths)
    scores = {}
    for family, (iv, block, icv) in LAYOUTS.items():
        scores[family] = sum(math.log(block / BASE_GRID) if _fits(n, iv, block, icv) else MISFIT_LOG_PENALTY for n in distinct)
    top = max(scores.values())
    weights = {family: math.exp(score - top) for family, score in scores.items()}
    total = sum(weights.values())
    return {family: weight / total for family, weight in weights.items()}


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return float(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]) if ordered else 0.0


def esp_structure(packets: list[PacketRecord]) -> dict:
    esp_all = [p for p in packets if p.esp_spi]
    lengths = [n for p in esp_all if (n := p.esp_payload_length) is not None and n > 0]
    if len(lengths) < MIN_PACKETS:
        return {"measured_packets": len(lengths), "features": {}, "note": f"At least {MIN_PACKETS} ESP packets with measurable lengths are needed"}

    readable = sum(1 for p in esp_all if p.esp_next_header is not None and "_ws.malformed" not in p.protocols) / len(esp_all)
    posterior = cipher_posterior(lengths)
    distinct = sorted(set(lengths))
    if readable >= 0.9:
        layout_family, layout, cipher_status = NULL_FAMILY, (0, 4, 16), "readable"
    else:
        layout_family = max(posterior, key=posterior.get)
        layout = LAYOUTS[layout_family]
        cipher_status = "inferred" if len(distinct) >= MIN_DISTINCT_LENGTHS else "ambiguous"

    iv, block, icv = layout
    # Inner size estimate: midpoint of the possible padding for each packet.
    inner = [n - iv - icv - 2 - (block - 1) / 2 for n in lengths]
    ipv6_outer = any(p.ip_version == "IPv6" for p in esp_all)
    frac = lambda low, high: sum(1 for x in inner if low <= x <= high) / len(inner)
    residues = Counter(n % 16 for n in lengths)
    features = {
        "esp_measured_packets": float(len(lengths)),
        "esp_distinct_lengths": float(len(distinct)),
        "esp_inner_min": min(inner),
        "esp_inner_p05": _percentile(inner, 0.05),
        "esp_inner_p10": _percentile(inner, 0.10),
        "esp_inner_p25": _percentile(inner, 0.25),
        "esp_inner_p50": _percentile(inner, 0.50),
        "esp_frac_inner_le_24": frac(0, 24),
        "esp_frac_inner_le_36": frac(0, 36),
        "esp_frac_inner_le_56": frac(0, 56),
        "esp_frac_inner_ack_transport": frac(14, 36),   # TCP ACK (20/32) without an inner IP header
        "esp_frac_inner_ack_tunnel": frac(36, 58),      # TCP ACK plus a 20-byte inner IPv4 header
        "esp_frac_inner_ack_tunnel_v6": frac(56, 78),   # TCP ACK plus a 40-byte inner IPv6 header
        # Largest possible size of the smallest inner packet under the chosen layout (zero padding).
        "esp_inner_upper_min": float(distinct[0] - iv - icv - 2),
        "esp_layout_decided": 1.0 if cipher_status != "ambiguous" else 0.0,
        "esp_outer_ipv6": 1.0 if ipv6_outer else 0.0,
        "esp_udp_encapsulated": 1.0 if any("udpencap" in p.protocols for p in esp_all) else 0.0,
        "esp_readable_fraction": readable,
    }
    top_residue, top_count = residues.most_common(1)[0]
    return {
        "measured_packets": len(lengths),
        "features": features,
        "cipher": {
            "status": cipher_status,
            "family": layout_family if cipher_status != "ambiguous" else None,
            "posterior": {family: round(p, 4) for family, p in posterior.items()} if cipher_status != "readable" else {NULL_FAMILY: 1.0},
            "layout": {"iv_bytes": iv, "padding_block": block, "icv_bytes": icv},
        },
        "summary": {
            "distinct_lengths": len(distinct),
            "dominant_residue_mod16": top_residue,
            "dominant_residue_share": round(top_count / len(lengths), 4),
            "smallest_payload": distinct[0],
            "smallest_inner_estimate": round(min(inner), 1),
            "readable_fraction": round(readable, 4),
        },
    }


ESP_FEATURES = [
    "esp_measured_packets", "esp_distinct_lengths", "esp_inner_min", "esp_inner_p05", "esp_inner_p10", "esp_inner_p25", "esp_inner_p50",
    "esp_frac_inner_le_24", "esp_frac_inner_le_36", "esp_frac_inner_le_56",
    "esp_frac_inner_ack_transport", "esp_frac_inner_ack_tunnel", "esp_frac_inner_ack_tunnel_v6",
    "esp_inner_upper_min", "esp_layout_decided", "esp_outer_ipv6", "esp_udp_encapsulated", "esp_readable_fraction",
]
