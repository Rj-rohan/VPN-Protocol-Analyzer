from pathlib import Path

from app.packet.features import extract_features
from app.packet.tshark import TSharkService
from app.security.findings import assess_security


def analyze_pcap(path: Path) -> dict:
    parsed = TSharkService().analyze(path)
    features = extract_features(parsed.packets, parsed.ike_packets)
    security = assess_security(features)
    return {
        "packet_count": parsed.packet_count,
        "detected_protocols": parsed.detected_protocols,
        "source": "tshark",
        "tshark_version": parsed.version,
        "warnings": parsed.warnings,
        "features": features,
        "security": security,
        "observability": {"encrypted_payloads": "not decrypted or content-inspected"},
    }
