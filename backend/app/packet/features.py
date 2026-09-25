"""Structured IPsec features built from TShark output.

Every value is labelled `observed`, `observed-majority`, `inferred` or
`unavailable`; missing values are never guessed.
"""
from __future__ import annotations

from collections import Counter
from math import prod

from app.packet import esp, ike, iana
from app.packet.observations import OBSERVED, INFERRED, UNKNOWN, observation, unavailable
from app.packet.esp_structure import esp_structure
from app.packet.rekey import analyze_rekeys
from app.packet.traffic import extract_traffic_metadata
from app.packet.tshark import PacketRecord

__all__ = ["UNKNOWN", "extract_features"]

# Weight of each independent piece of detection evidence. Combined as
# 1 - prod(1 - w): a transparent heuristic, not a calibrated probability.
DETECTION_WEIGHTS = {
    "ike_header": 0.6,
    "ike_bidirectional": 0.3,
    "esp_ip_protocol_50": 0.6,
    "esp_udp_encapsulated": 0.4,
    "esp_sequence_progression": 0.3,
    "ah_ip_protocol_51": 0.6,
}
CONFIDENCE_METHOD = "Evidence-weighted heuristic 1 - prod(1 - w) over the evidence present; not a calibrated probability"


def _detection(packets: list[PacketRecord], messages: list[ike.IkeMessage], indicators: dict) -> dict:
    esp_all = esp.esp_packets(packets)
    udp_esp = [p for p in esp_all if esp.udp_encapsulated(p)]
    items: list[tuple[str, str]] = []
    versioned = [m for m in messages if m.version]
    if versioned:
        items.append(("ike_header", f"{len(versioned)} ISAKMP header(s) with a recognised IKE version"))
    if any(m.is_response or (m.version == "IKEv1" and m.responder_spi_set) for m in messages):
        items.append(("ike_bidirectional", "Both IKE requests and responses were captured"))
    if len(esp_all) > len(udp_esp):
        items.append(("esp_ip_protocol_50", f"{len(esp_all) - len(udp_esp)} ESP packet(s) on IP protocol 50"))
    if udp_esp:
        items.append(("esp_udp_encapsulated", f"{len(udp_esp)} UDP-encapsulated ESP packet(s) on port 4500"))
    if indicators["spis_with_strictly_increasing_sequences"] and indicators["packets_with_sequence_numbers"] > indicators["spi_count"]:
        items.append(("esp_sequence_progression", "ESP/AH sequence numbers increase consistently within an SPI"))
    if esp.ah_packets(packets):
        items.append(("ah_ip_protocol_51", f"{len(esp.ah_packets(packets))} AH packet(s) on IP protocol 51"))
    confidence = 1 - prod(1 - DETECTION_WEIGHTS[key] for key, _ in items) if items else 0.0
    return {
        "ipsec_detected": bool(messages or esp_all or esp.ah_packets(packets)),
        "ike_detected": bool(messages),
        "esp_detected": bool(esp_all),
        "ah_detected": bool(esp.ah_packets(packets)),
        "ike_version": ike.ike_version(messages)["value"],
        "confidence": round(confidence, 2),
        "confidence_method": CONFIDENCE_METHOD,
        "evidence": [text for _, text in items],
    }


def _ipsec_protocol(packets: list[PacketRecord]) -> str:
    found = [name for name, present in (("ESP", esp.esp_packets(packets)), ("AH", esp.ah_packets(packets))) if present]
    return " + ".join(found) if found else UNKNOWN


def _ip_version(packets: list[PacketRecord], messages: list[ike.IkeMessage]) -> dict:
    ike_frames = {m.frame_number for m in messages}
    ipsec = [p for p in packets if p.esp_spi or p.ah_spi or p.frame_number in ike_frames]
    scope = "IPsec" if ipsec else "all"
    versions = Counter(p.ip_version for p in (ipsec or packets) if p.ip_version)
    if not versions:
        return unavailable("No IP layer was exposed")
    return observation(", ".join(sorted(versions)), OBSERVED, [f"{count} {scope} packet(s) use outer {version}" for version, count in sorted(versions.items())])


def _spi_values(packets: list[PacketRecord]) -> dict:
    spis = sorted({p.esp_spi for p in packets if p.esp_spi} | {p.ah_spi for p in packets if p.ah_spi})
    if not spis:
        return unavailable("No ESP or AH SPI was observed")
    return observation(spis, OBSERVED, [f"{len(spis)} distinct ESP/AH SPI value(s) observed"])


def _nat_traversal(packets: list[PacketRecord], messages: list[ike.IkeMessage]) -> dict:
    # NAT-T means UDP encapsulation of ESP (RFC 3948). IKE on port 4500 alone is not proof:
    # MOBIKE implementations such as strongSwan move IKE to 4500 even when no NAT is present.
    esp_all = esp.esp_packets(packets)
    udp_esp = [p for p in esp_all if esp.udp_encapsulated(p)]
    raw_esp = len(esp_all) - len(udp_esp)
    ike_4500 = [m for m in messages if m.uses_port_4500]
    nat_detection = any(n in iana.NOTIFY_NAT_DETECTION for m in messages for n in m.notify_types)
    if udp_esp:
        evidence = [f"{len(udp_esp)} ESP packet(s) are UDP-encapsulated on port 4500"]
        if nat_detection:
            evidence.append("NAT detection payloads were exchanged")
        return observation(True, OBSERVED, evidence)
    if raw_esp:
        evidence = [f"{raw_esp} ESP packet(s) are carried directly as IP protocol 50 without UDP encapsulation"]
        if ike_4500:
            evidence.append(f"{len(ike_4500)} IKE message(s) moved to UDP 4500 (port floating/MOBIKE), but ESP was not encapsulated")
        return observation(False, OBSERVED, evidence)
    if ah := esp.ah_packets(packets):
        # UDP encapsulation (RFC 3948) exists only for ESP; AH authenticates the IP addresses, so it cannot cross a NAT.
        return observation(False, OBSERVED, [f"{len(ah)} AH packet(s) carried directly as IP protocol 51; AH cannot be UDP-encapsulated for NAT traversal"])
    if ike_4500:
        return unavailable(f"{len(ike_4500)} IKE message(s) use UDP 4500, which happens with NAT-T and with MOBIKE; no ESP traffic shows which applies")
    # NAT-T moves IKE to port 4500 from IKE_AUTH (IKEv2) or before Quick Mode (IKEv1).
    later = [m for m in messages if 500 in m.ports and (
        (m.version == "IKEv2" and m.exchange_type in (35, 36, 37)) or (m.version == "IKEv1" and m.exchange_type == 32))]
    if later:
        return observation(False, INFERRED, [f"{len(later)} IKE message(s) after the initial exchange stayed on UDP port 500, where NAT-T would have moved to 4500"])
    if nat_detection:
        return unavailable("NAT detection payloads were exchanged, but the capture ends before any switch to UDP 4500 would occur")
    return unavailable("No NAT-T port or NAT detection evidence was observed")


def extract_features(packets: list[PacketRecord], ike_packets: list[dict]) -> dict:
    messages = ike.parse_messages(ike_packets)
    # Timestamps come from the metadata pass (numeric); TShark's JSON renders frame.time_epoch as a date string.
    frame_times = {p.frame_number: p.timestamp for p in packets}
    for message in messages:
        message.timestamp = frame_times.get(message.frame_number, message.timestamp)
    indicators = esp.replay_indicators(packets)
    esp_all = esp.esp_packets(packets)
    crypto = ike.cryptography(messages)
    rekeys = analyze_rekeys(messages, packets, crypto["encryption_algorithm"]["value"], crypto["integrity_algorithm"]["value"],
                            crypto["dh_group"]["value"])
    if crypto["pfs"]["value"] == UNKNOWN and (rekey_pfs := rekeys.get("pfs")) and rekey_pfs["value"] != UNKNOWN:
        crypto["pfs"] = rekey_pfs  # inferred from CREATE_CHILD_SA sizes when the negotiation itself is encrypted
    no_rekey = rekeys.get("reason", "No rekey of this kind was observed")
    return {
        "detection": _detection(packets, messages, indicators),
        "protocol": {
            "ipsec_protocol": _ipsec_protocol(packets),
            "ike_version": ike.ike_version(messages),
            "ike_exchange_types": ike.exchange_types(messages),
            "ip_version": _ip_version(packets, messages),
        },
        "mode": esp.mode(packets, ike.mode(messages)),
        "cryptography": crypto,
        "sa": {
            "sa_lifetime_seconds": ike.sa_lifetime(messages),
            "child_rekey_interval_seconds": rekeys.get("child_interval") or unavailable(no_rekey),
            "ike_rekey_interval_seconds": rekeys.get("ike_interval") or unavailable(no_rekey),
            "spi_values": _spi_values(packets),
            "replay_protection": esp.replay_protection(indicators),
            "payload_confidentiality": esp.payload_confidentiality(packets),
            "nat_traversal": _nat_traversal(packets, messages),
        },
        "replay_indicators": indicators,
        "rekeys": {"child_rekeys": rekeys.get("child_rekeys", 0), "ike_rekeys": rekeys.get("ike_rekeys", 0)},
        "ike_proposals": ike.proposal_summary(messages),
        "traffic": extract_traffic_metadata(packets, messages),
        "esp_structure": esp_structure(packets),
        "packet_statistics": {
            "packet_count": len(packets),
            "ike_message_count": len(messages),
            "esp_packet_count": len(esp_all),
            "udp_encapsulated_esp_count": sum(1 for p in esp_all if esp.udp_encapsulated(p)),
            "ah_packet_count": len(esp.ah_packets(packets)),
        },
    }
