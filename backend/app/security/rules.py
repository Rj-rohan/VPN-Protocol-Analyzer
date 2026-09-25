from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable

UNKNOWN = "Unknown / Not observable"


@dataclass(frozen=True)
class SecurityFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    condition: str
    evidence: str
    impact: str
    recommendation: str
    source: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "condition": self.condition,
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "source": self.source,
        }


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    title: str
    description: str
    severity: str
    condition: str
    recommendation: str
    evaluator: Callable[[dict], tuple[bool, str, str, str]]

    def evaluate(self, features: dict) -> SecurityFinding | None:
        triggered, evidence, impact, source = self.evaluator(features)
        if not triggered:
            return None
        return SecurityFinding(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            condition=self.condition,
            evidence=evidence,
            impact=impact,
            recommendation=self.recommendation,
            source=source,
        )


def _value(features: dict, *path: str):
    current = features
    for key in path:
        if not isinstance(current, dict):
            return UNKNOWN
        current = current.get(key, {})
    if isinstance(current, dict) and "value" in current:
        return current["value"]
    return current if current else UNKNOWN


def _observation(features: dict, *path: str) -> dict:
    current = features
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key, {})
    return current if isinstance(current, dict) else {}


def _text(value) -> str:
    return str(value).lower() if value != UNKNOWN else ""


def _finding_unknown(features: dict) -> tuple[bool, str, str, str]:
    paths = (
        (("protocol", "ike_version"), "IKE version"),
        (("cryptography", "encryption_algorithm"), "encryption"),
        (("cryptography", "integrity_algorithm"), "integrity"),
        (("cryptography", "authentication_method"), "authentication method"),
        (("cryptography", "dh_group"), "DH group"),
        (("cryptography", "pfs"), "PFS"),
        (("sa", "replay_protection"), "replay protection"),
    )
    # Without IPsec there are no IPsec parameters to observe; "not observable" would mislead.
    if not features.get("detection", {}).get("ipsec_detected"):
        return False, "", "", ""
    unknown = [label for path, label in paths if _value(features, *path) == UNKNOWN]
    if not unknown:
        return False, "", "", ""
    return True, f"Not observable in this capture: {', '.join(unknown)}", "Unobservable parameters reduce assurance and require configuration-side verification.", "observed"


def _ikev1(features: dict) -> tuple[bool, str, str, str]:
    value = _value(features, "protocol", "ike_version")
    return "IKEv1" in str(value), f"IKE version observed as {value}.", "Legacy negotiation may lack modern protocol protections and policy controls.", _observation(features, "protocol", "ike_version").get("source", "observed")


# MODP-768, MODP-1024, MODP-1536, MODP-1024 with 160-bit subgroup, ECP-192.
WEAK_DH_GROUPS = {1, 2, 5, 22, 25}


def _weak_dh(features: dict) -> tuple[bool, str, str, str]:
    raw = _value(features, "cryptography", "dh_group")
    value = _text(raw)
    match = re.search(r"\b(?:dh|group)\s*(\d+)\b", value)
    weak = (match is not None and int(match.group(1)) in WEAK_DH_GROUPS) or any(token in value for token in ("modp-768", "modp-1024", "modp-1536"))
    return weak, f"DH group observed as {raw}.", "Weak or legacy groups reduce resistance to key-recovery attacks.", _observation(features, "cryptography", "dh_group").get("source", "observed")


def _legacy_integrity(features: dict) -> tuple[bool, str, str, str]:
    value = _text(_value(features, "cryptography", "integrity_algorithm"))
    weak = any(token in value for token in ("sha1", "sha-1", "md5", "hmac-md5"))
    return weak, f"Integrity transform observed as {_value(features, 'cryptography', 'integrity_algorithm')}.", "Legacy integrity algorithms have reduced collision or security margins.", _observation(features, "cryptography", "integrity_algorithm").get("source", "observed")


def _pfs_disabled(features: dict) -> tuple[bool, str, str, str]:
    value = _value(features, "cryptography", "pfs")
    return value is False, "PFS was explicitly observed as disabled.", "Compromise of a long-term key can expose more session material without forward secrecy.", _observation(features, "cryptography", "pfs").get("source", "observed")


def _replay_disabled(features: dict) -> tuple[bool, str, str, str]:
    value = _value(features, "sa", "replay_protection")
    return value is False, "Replay protection was explicitly observed as disabled.", "Captured packets may be more susceptible to replay attacks.", _observation(features, "sa", "replay_protection").get("source", "observed")


def _long_lifetime(features: dict) -> tuple[bool, str, str, str]:
    value = _value(features, "sa", "sa_lifetime_seconds")
    triggered = isinstance(value, int) and value > 86400
    return triggered, f"SA lifetime observed as {value} seconds.", "Long-lived keys increase the amount of traffic protected by one key and extend exposure after policy changes.", _observation(features, "sa", "sa_lifetime_seconds").get("source", "observed")


def _weak_cipher(features: dict) -> tuple[bool, str, str, str]:
    value = _text(_value(features, "cryptography", "encryption_algorithm"))
    weak = any(token in value for token in ("des", "3des", "3-des", "null", "rc4", "blowfish"))
    return weak, f"Encryption transform observed as {_value(features, 'cryptography', 'encryption_algorithm')}.", "The encryption choice may provide inadequate confidentiality or policy compliance.", _observation(features, "cryptography", "encryption_algorithm").get("source", "observed")


def _suspicious_combination(features: dict) -> tuple[bool, str, str, str]:
    encryption = _text(_value(features, "cryptography", "encryption_algorithm"))
    integrity = _text(_value(features, "cryptography", "integrity_algorithm"))
    aead = any(token in encryption for token in ("gcm", "ccm", "chacha20-poly1305"))
    if aead and integrity not in {"", "aead"}:
        return True, f"AEAD encryption {encryption} was observed with separate integrity {integrity}.", "An inconsistent proposal may cause negotiation downgrade, interoperability issues, or policy ambiguity.", "observed"
    if encryption and not aead and integrity == "none":
        return True, f"Non-AEAD encryption {encryption} was observed with no integrity transform.", "Encryption without integrity protection allows undetected modification of protected traffic.", "observed"
    return False, "", "", ""


def _payload_unencrypted(features: dict) -> tuple[bool, str, str, str]:
    observed = _observation(features, "sa", "payload_confidentiality")
    triggered = observed.get("value") is False
    evidence = "; ".join(observed.get("evidence", []))
    return triggered, evidence, "Protected traffic is readable by anyone on the path; IPsec provides integrity only.", observed.get("source", "observed")


def _aggressive_mode(features: dict) -> tuple[bool, str, str, str]:
    exchanges = _value(features, "protocol", "ike_exchange_types")
    triggered = isinstance(exchanges, list) and "Aggressive Mode" in exchanges
    return triggered, "IKEv1 Aggressive Mode exchange observed.", "Aggressive Mode sends identities in cleartext and, with pre-shared keys, exposes a hash that can be attacked offline.", "observed"


PREDICTION_THRESHOLD = 0.8
EXPOSURE_IMPACT = "The communicating hosts' real addresses are visible to on-path observers; tunnel mode hides internal addressing."


def _prediction(features: dict, target: str) -> dict:
    inference = features.get("inference") or {}
    entry = inference.get(target) if inference.get("status") == "predicted" else None
    return entry if isinstance(entry, dict) and (entry.get("confidence") or 0) >= PREDICTION_THRESHOLD else {}


def _transport_exposure(features: dict) -> tuple[bool, str, str, str]:
    observed = _observation(features, "mode")
    if observed.get("value") == "Transport":
        return True, f"Transport mode: {'; '.join(observed.get('evidence', []))}", EXPOSURE_IMPACT, observed.get("source", "observed")
    predicted = _prediction(features, "mode")
    if observed.get("value") in ("Unknown", None) and predicted.get("label") == "Transport":
        return True, (f"AI prediction: transport mode ({predicted['confidence']:.0%} confidence) from ESP packet-length patterns; "
                      "confirm on the VPN endpoints"), EXPOSURE_IMPACT, "predicted"
    return False, "", "", ""


def _block64_cipher(features: dict) -> tuple[bool, str, str, str]:
    predicted = _prediction(features, "esp_cipher")
    triggered = predicted.get("label", "").startswith("64-bit block")
    evidence = (f"AI prediction: {predicted.get('label')} ({predicted.get('confidence', 0):.0%} confidence); ESP payload lengths fit an "
                "8-byte cipher block but not a 16-byte one") if triggered else ""
    return triggered, evidence, "64-bit block ciphers (3DES, Blowfish) are exposed to birthday attacks (Sweet32) on long-lived SAs.", "predicted"


def _pattern_exposure(features: dict) -> tuple[bool, str, str, str]:
    traffic = _observation(features, "traffic").get("features", {})
    packets = traffic.get("flow_packet_count", 0)
    spread = traffic.get("std_packet_size_bytes", 0.0)
    triggered = packets >= 20 and spread > 0
    evidence = (f"{packets} ESP/AH packets with size standard deviation {spread:.1f} bytes, "
                f"{traffic.get('packets_per_second', 0):.1f} packets/s; sizes and timing track the protected traffic")
    return triggered, evidence, "Packet sizes, timing and direction let observers infer the type of protected traffic without decryption.", "observed"


RULES = (
    SecurityRule("PROTO-001", "Legacy IKE version", "IKEv1 was observed in the negotiation.", "High", "protocol.ike_version == IKEv1", "Migrate to IKEv2 with an approved modern proposal set and remove IKEv1 where possible.", _ikev1),
    SecurityRule("CRYPTO-001", "Weak or legacy DH group", "The observed DH group matches a known legacy group pattern.", "High", "cryptography.dh_group is a legacy group", "Use an organizationally approved modern DH group and validate the complete proposal set.", _weak_dh),
    SecurityRule("CRYPTO-002", "Legacy integrity algorithm", "A legacy hash or integrity transform was observed.", "High", "cryptography.integrity_algorithm contains SHA-1 or MD5", "Use modern integrity or AEAD proposals according to organizational policy.", _legacy_integrity),
    SecurityRule("CRYPTO-003", "PFS disabled", "The capture explicitly reports PFS disabled.", "High", "cryptography.pfs == false", "Enable PFS for child SAs where supported by the deployment policy.", _pfs_disabled),
    SecurityRule("SA-001", "Replay protection disabled", "The capture explicitly reports replay protection disabled.", "High", "sa.replay_protection == false", "Enable anti-replay protection and verify the configured replay window.", _replay_disabled),
    SecurityRule("SA-002", "Excessive SA lifetime", "The observed SA lifetime exceeds the project review threshold.", "Medium", "sa.sa_lifetime_seconds > 86400", "Review and shorten SA lifetimes according to operational risk and rekey policy.", _long_lifetime),
    SecurityRule("CRYPTO-004", "Weak cipher configuration", "A legacy or non-confidentiality cipher was observed.", "Critical", "cryptography.encryption_algorithm contains DES, 3DES, NULL, RC4, or Blowfish", "Remove legacy ciphers and require approved authenticated encryption or modern encryption/integrity pairs.", _weak_cipher),
    SecurityRule("CONFIG-001", "Suspicious transform combination", "The observed proposal combines transforms inconsistently.", "Medium", "AEAD encryption with a separate integrity transform, or non-AEAD encryption with integrity NONE", "Review the negotiated proposal for downgrade or configuration mismatch.", _suspicious_combination),
    SecurityRule("CRYPTO-005", "Payload not encrypted", "ESP-NULL or AH-only protection was observed, so payloads travel in cleartext.", "Critical", "sa.payload_confidentiality == false", "Use an encrypting ESP transform (for example AES-GCM) for all traffic that requires confidentiality.", _payload_unencrypted),
    SecurityRule("CRYPTO-006", "64-bit block ESP cipher suspected", "ESP packet lengths indicate a 64-bit block cipher such as 3DES or Blowfish.", "Medium", "AI esp_cipher prediction = 64-bit block cipher with confidence >= 0.8", "Replace 3DES/Blowfish ESP transforms with AES-GCM and verify the child SA proposal on the endpoints.", _block64_cipher),
    SecurityRule("PROTO-002", "IKEv1 Aggressive Mode", "The negotiation used IKEv1 Aggressive Mode.", "High", "'Aggressive Mode' in protocol.ike_exchange_types", "Disable Aggressive Mode; migrate to IKEv2, or at least use Main Mode with certificate authentication.", _aggressive_mode),
    SecurityRule("META-001", "Endpoint addresses exposed (transport mode)", "Transport mode protects payloads but leaves the hosts' real IP addresses visible.", "Low", "mode == Transport (observed, or AI-predicted with confidence >= 0.8)", "Use tunnel mode between gateways where internal addressing should not be visible, per deployment policy.", _transport_exposure),
    SecurityRule("META-002", "Traffic pattern metadata exposure", "Encrypted packet sizes and timing vary with the protected traffic.", "Low", "ESP/AH flow >= 20 packets with varying packet sizes", "Where traffic-analysis resistance is required, evaluate ESP traffic flow confidentiality padding (RFC 4303 section 2.7) or dummy traffic.", _pattern_exposure),
    SecurityRule("OBS-001", "Security parameters not observable", "One or more security parameters were absent from the capture.", "Low", "one or more required observations are unavailable", "Validate the configuration on the VPN endpoints and retain negotiation captures that expose the required fields.", _finding_unknown),
)


def evaluate_rules(features: dict) -> list[dict]:
    return [finding.as_dict() for rule in RULES if (finding := rule.evaluate(features)) is not None]