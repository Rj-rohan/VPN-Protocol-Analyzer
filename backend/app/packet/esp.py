"""ESP/AH analysis from per-packet TShark metadata."""
from __future__ import annotations

from collections import defaultdict

from app.packet.observations import INFERRED, OBSERVED, observation, unavailable
from app.packet.tshark import PacketRecord

# A random encrypted trailer occasionally passes the ESP-NULL heuristic, so a
# mode is only inferred when nearly every packet on an SPI decodes consistently.
NULL_DECODE_THRESHOLD = 0.9
TUNNEL_NEXT_HEADERS = {4: "IPv4", 41: "IPv6"}
TRANSPORT_NEXT_HEADERS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 132: "SCTP"}
TUNNEL_LAYERS = {"ip", "ipv6"}
TRANSPORT_LAYERS = {"tcp", "udp", "icmp", "icmpv6", "sctp"}


def esp_packets(packets: list[PacketRecord]) -> list[PacketRecord]:
    return [packet for packet in packets if packet.esp_spi]


def ah_packets(packets: list[PacketRecord]) -> list[PacketRecord]:
    return [packet for packet in packets if packet.ah_spi]


def udp_encapsulated(packet: PacketRecord) -> bool:
    return "udpencap" in packet.protocols


def by_spi(packets: list[PacketRecord], attribute: str = "esp_spi") -> dict[str, list[PacketRecord]]:
    groups: dict[str, list[PacketRecord]] = defaultdict(list)
    for packet in packets:
        if spi := getattr(packet, attribute):
            groups[spi].append(packet)
    return dict(groups)


def _layer_after(packet: PacketRecord, name: str) -> str | None:
    if name not in packet.protocols:
        return None
    index = packet.protocols.index(name)
    return packet.protocols[index + 1] if index + 1 < len(packet.protocols) else None


def _ah_mode(packets: list[PacketRecord]) -> tuple[str, str, list[str]] | None:
    # AH authenticates but does not encrypt, so the next header is always readable.
    ah = ah_packets(packets)
    tunnel = sum(1 for p in ah if _layer_after(p, "ah") in TUNNEL_LAYERS)
    transport = sum(1 for p in ah if _layer_after(p, "ah") in TRANSPORT_LAYERS)
    if tunnel and not transport:
        return "Tunnel", OBSERVED, [f"{tunnel} AH packet(s) carry an inner IP header"]
    if transport and not tunnel:
        return "Transport", OBSERVED, [f"{transport} AH packet(s) carry a transport-layer header directly"]
    if tunnel and transport:
        return "Mixed", OBSERVED, [f"AH packets show both inner IP headers ({tunnel}) and direct transport headers ({transport})"]
    return None


def _esp_null_mode(packets: list[PacketRecord]) -> tuple[str, str, list[str]] | None:
    modes: set[str] = set()
    evidence: list[str] = []
    for spi, group in by_spi(esp_packets(packets)).items():
        valid = [p for p in group if p.esp_next_header is not None and "_ws.malformed" not in p.protocols]
        tunnel = sum(1 for p in valid if p.esp_next_header in TUNNEL_NEXT_HEADERS and _layer_after(p, "esp") in TUNNEL_LAYERS)
        transport = sum(1 for p in valid if p.esp_next_header in TRANSPORT_NEXT_HEADERS)
        for label, count, detail in (("Tunnel", tunnel, "an inner IP header"), ("Transport", transport, "a transport-layer next header")):
            if count and count / len(group) >= NULL_DECODE_THRESHOLD:
                modes.add(label)
                evidence.append(f"SPI {spi}: {count}/{len(group)} ESP packets decode as ESP-NULL with {detail}")
    if not modes:
        return None
    return ("Mixed" if len(modes) > 1 else modes.pop()), INFERRED, evidence


def cleartext_esp_spis(packets: list[PacketRecord]) -> dict[str, tuple[int, int]]:
    """SPIs whose packets consistently decode as ESP-NULL: {spi: (decoded, total)}."""
    found = {}
    for spi, group in by_spi(esp_packets(packets)).items():
        decoded = sum(1 for p in group if p.esp_next_header is not None and "_ws.malformed" not in p.protocols
                      and (p.esp_next_header in TUNNEL_NEXT_HEADERS or p.esp_next_header in TRANSPORT_NEXT_HEADERS))
        if decoded and decoded / len(group) >= NULL_DECODE_THRESHOLD:
            found[spi] = (decoded, len(group))
    return found


def payload_confidentiality(packets: list[PacketRecord]) -> dict:
    esp_all, ah_all = esp_packets(packets), ah_packets(packets)
    cleartext = cleartext_esp_spis(packets)
    if cleartext:
        return observation(False, OBSERVED, [
            f"SPI {spi}: {decoded}/{total} ESP packets carry a readable inner header (ESP-NULL, no encryption)"
            for spi, (decoded, total) in cleartext.items()
        ])
    if esp_all:
        return observation(True, INFERRED, ["ESP payloads do not parse as cleartext headers, consistent with encryption"])
    if ah_all:
        return observation(False, OBSERVED, ["Only AH was observed; AH authenticates packets but does not encrypt them"])
    return unavailable("No ESP or AH traffic was observed")


def mode(packets: list[PacketRecord], ike_mode: dict | None) -> dict:
    if ike_mode:
        return {**ike_mode, "confidence": 0.95}
    for finder, confidence in ((_ah_mode, 0.95), (_esp_null_mode, 0.9)):
        if result := finder(packets):
            value, source, evidence = result
            return {**observation(value, source, evidence), "confidence": confidence}
    evidence = ["No IKE mode negotiation was visible (IKEv1 Quick Mode and IKEv2 IKE_AUTH are encrypted)"]
    if esp_packets(packets):
        evidence.insert(0, "ESP payloads are encrypted, so the inner header that distinguishes tunnel from transport mode is not visible")
    return {**observation("Unknown", "unavailable", evidence), "confidence": 0.0}


def replay_indicators(packets: list[PacketRecord]) -> dict:
    groups = {**by_spi(esp_packets(packets)), **by_spi(ah_packets(packets), "ah_spi")}
    increasing = duplicates = out_of_order = with_sequence = 0
    for group in groups.values():
        sequences = [p.esp_sequence if p.esp_spi else p.ah_sequence for p in group]
        sequences = [s for s in sequences if s is not None]
        with_sequence += len(sequences)
        duplicates += len(sequences) - len(set(sequences))
        highest = None
        spi_out_of_order = 0
        for sequence in sequences:
            if highest is not None and sequence < highest:
                spi_out_of_order += 1
            highest = sequence if highest is None else max(highest, sequence)
        out_of_order += spi_out_of_order
        if sequences and spi_out_of_order == 0 and len(sequences) == len(set(sequences)):
            increasing += 1
    return {
        "spi_count": len(groups),
        "packets_with_sequence_numbers": with_sequence,
        "spis_with_strictly_increasing_sequences": increasing,
        "duplicate_sequence_numbers": duplicates,
        "out_of_order_sequence_numbers": out_of_order,
    }


def replay_protection(indicators: dict) -> dict:
    if not indicators["packets_with_sequence_numbers"]:
        return unavailable("No ESP/AH sequence numbers were observed")
    evidence = [
        f"Sequence numbers observed on {indicators['spi_count']} SPI(s); "
        f"{indicators['spis_with_strictly_increasing_sequences']} strictly increasing",
        "RFC 4303 senders always increment sequence numbers; whether the receiver enforces an anti-replay window cannot be observed on the wire",
    ]
    if indicators["duplicate_sequence_numbers"]:
        evidence.append(
            f"{indicators['duplicate_sequence_numbers']} duplicate sequence number(s) seen; these can come from capture duplication, "
            "retransmission or an actual replay attempt"
        )
    return unavailable(*evidence)
