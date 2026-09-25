"""IKE/ISAKMP message parsing from TShark JSON (`-T json --no-duplicate-keys`).

Only cleartext negotiation is available to the parser: IKEv2 IKE_SA_INIT and
IKEv1 Main/Aggressive Mode. IKE_AUTH, CREATE_CHILD_SA and Quick Mode are
encrypted, so child SA transforms, PFS and IKEv2 authentication are reported as
unavailable unless a decrypted capture exposes them.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from app.packet import iana
from app.packet.field_map import IKE_FIELDS as F
from app.packet.observations import INFERRED, OBSERVED, OBSERVED_MAJORITY, UNKNOWN, observation, unavailable

NOTIFY_NO_PROPOSAL_CHOSEN = 14
IKEV2_KE_PAYLOAD = 34
SCOPE_NOTE = (
    "Applies to the IKE SA negotiated in cleartext; ESP child SA transforms are negotiated "
    "inside encrypted IKE messages and may differ."
)


def _scalar(value: Any) -> str | None:
    while isinstance(value, list):
        if not value:
            return None
        value = value[0]
    return value if isinstance(value, str) else None


def _int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _float(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def _dicts_with(node: Any, key: str) -> Iterator[dict]:
    if isinstance(node, dict):
        if key in node:
            yield node
        for child in node.values():
            yield from _dicts_with(child, key)
    elif isinstance(node, list):
        for child in node:
            yield from _dicts_with(child, key)


def _values(node: Any, key: str) -> list[str]:
    found: list[str] = []
    for container in _dicts_with(node, key):
        value = container[key]
        found += [item for item in (value if isinstance(value, list) else [value]) if isinstance(item, str)]
    return found


def _ints(node: Any, key: str) -> list[int]:
    return [number for value in _values(node, key) if (number := _int(value)) is not None]


def _first_int(node: Any, key: str) -> int | None:
    numbers = _ints(node, key)
    return numbers[0] if numbers else None


def _layer(layers: dict, name: str) -> dict:
    value = layers.get(name)
    if isinstance(value, list):
        value = next((item for item in value if isinstance(item, dict)), None)
    return value if isinstance(value, dict) else {}


@dataclass
class Proposal:
    version: str | None
    protocol: str
    encryption: list[str] = field(default_factory=list)
    integrity: list[str] = field(default_factory=list)
    prf: list[str] = field(default_factory=list)
    dh: list[str] = field(default_factory=list)
    dh_ids: list[int] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    lifetime_seconds: list[int] = field(default_factory=list)
    lifetime_kilobytes: list[int] = field(default_factory=list)
    encapsulation_modes: list[str] = field(default_factory=list)

    def signature(self) -> tuple:
        return (self.version, self.protocol, *(tuple(values) for values in (
            self.encryption, self.integrity, self.prf, self.dh, self.authentication,
            self.lifetime_seconds, self.lifetime_kilobytes, self.encapsulation_modes,
        )))

    def as_dict(self) -> dict:
        data = {"ike_version": self.version, "protocol": self.protocol}
        for key in ("encryption", "integrity", "prf", "dh", "authentication", "lifetime_seconds", "lifetime_kilobytes", "encapsulation_modes"):
            if values := getattr(self, key):
                data[key] = values
        return data


@dataclass
class IkeMessage:
    frame_number: int | None
    version: str | None
    exchange_type: int | None
    is_response: bool | None
    responder_spi_set: bool
    proposals: list[Proposal]
    notify_types: list[int]
    payload_types: list[int]
    auth_methods: list[int]
    ports: tuple[int | None, int | None]
    length: int | None = None        # total IKE message length (header included)
    timestamp: float | None = None

    @property
    def exchange_name(self) -> str:
        if self.exchange_type is None:
            return "Unknown exchange"
        table = iana.IKEV1_EXCHANGE_TYPES if self.version == "IKEv1" else iana.IKEV2_EXCHANGE_TYPES
        return table.get(self.exchange_type) or iana.IKEV1_EXCHANGE_TYPES.get(self.exchange_type) or iana.IKEV2_EXCHANGE_TYPES.get(self.exchange_type) or f"Exchange type {self.exchange_type}"

    @property
    def carries_selection(self) -> bool:
        """True when the SA payload is the responder's choice rather than the initiator's offer."""
        if not self.proposals:
            return False
        if self.version == "IKEv2":
            return bool(self.is_response)
        # IKEv1 Main/Aggressive Mode: only the responder's reply has a non-zero responder cookie and an SA payload.
        return self.version == "IKEv1" and self.responder_spi_set and self.exchange_type in (2, 4)

    @property
    def uses_port_4500(self) -> bool:
        return 4500 in self.ports


def _parse_v2_proposal(node: dict, protocol: str) -> Proposal:
    proposal = Proposal("IKEv2", protocol)
    aead = False
    integrity_ids: list[int] = []
    for transform in _dicts_with(node, F["v2_transform_type"]):
        kind = _int(_scalar(transform[F["v2_transform_type"]]))
        if kind == 1 and (encr := _int(_scalar(transform.get(F["v2_encr"])))) is not None:
            proposal.encryption.append(iana.ikev2_encryption_name(encr, _first_int(transform, F["v2_key_length"])))
            aead = aead or encr in iana.IKEV2_AEAD_ENCR
        elif kind == 2 and (prf := _int(_scalar(transform.get(F["v2_prf"])))) is not None:
            proposal.prf.append(iana.lookup(iana.IKEV2_PRF, prf, "PRF"))
        elif kind == 3 and (integ := _int(_scalar(transform.get(F["v2_integ"])))) is not None:
            integrity_ids.append(integ)
        elif kind == 4 and (group := _int(_scalar(transform.get(F["v2_dh"])))) is not None:
            proposal.dh_ids.append(group)
            proposal.dh.append(iana.dh_group_name(group))
    meaningful = [integ for integ in integrity_ids if integ != 0]
    if aead and not meaningful:
        proposal.integrity.append("AEAD")
    else:
        proposal.integrity += [iana.lookup(iana.IKEV2_INTEG, integ, "INTEG") for integ in integrity_ids]
    return proposal


def _parse_v1_proposal(node: dict, protocol: str) -> Proposal:
    proposal = Proposal("IKEv1", protocol)
    for transform in _dicts_with(node, F["v1_transform_id"]):
        if protocol == "IKE":
            if (encryption := _first_int(transform, F["v1_encryption"])) is not None:
                proposal.encryption.append(iana.ikev1_encryption_name(encryption, _first_int(transform, F["v1_key_length"])))
            if (hash_alg := _first_int(transform, F["v1_hash"])) is not None:
                proposal.integrity.append(iana.lookup(iana.IKEV1_HASH, hash_alg, "Hash algorithm"))
            if (auth := _first_int(transform, F["v1_auth"])) is not None:
                proposal.authentication.append(iana.lookup(iana.IKEV1_AUTH_METHODS, auth, "Authentication method"))
            if (group := _first_int(transform, F["v1_group"])) is not None:
                proposal.dh_ids.append(group)
                proposal.dh.append(iana.dh_group_name(group))
            for life_type, duration in zip(_ints(transform, F["v1_life_type"]), _ints(transform, F["v1_life_duration"])):
                (proposal.lifetime_seconds if life_type == 1 else proposal.lifetime_kilobytes).append(duration)
        else:
            # Phase-2 (IPsec DOI) transform IDs share the IKEv2 ENCR numbering for ESP.
            if protocol == "ESP" and (transform_id := _first_int(transform, F["v1_transform_id"])) is not None:
                proposal.encryption.append(iana.ikev2_encryption_name(transform_id, None))
            if (group := _first_int(transform, F["v1_ipsec_group"])) is not None:
                proposal.dh_ids.append(group)
                proposal.dh.append(iana.dh_group_name(group))
            if (mode := _first_int(transform, F["v1_ipsec_encap_mode"])) is not None:
                proposal.encapsulation_modes.append(iana.lookup(iana.IKEV1_ENCAP_MODES, mode, "Encapsulation mode"))
    return proposal


def _version(raw: str | None) -> str | None:
    number = _int(raw)
    if number is None:
        return None
    return {1: "IKEv1", 2: "IKEv2"}.get(number >> 4)


def parse_messages(ike_packets: list[dict]) -> list[IkeMessage]:
    messages: list[IkeMessage] = []
    for packet in ike_packets:
        layers = packet.get("_source", {}).get("layers", {})
        frame = _layer(layers, "frame")
        udp = _layer(layers, "udp")
        raw_isakmp = layers.get("isakmp")
        for isakmp in raw_isakmp if isinstance(raw_isakmp, list) else [raw_isakmp]:
            if not isinstance(isakmp, dict):
                continue
            version = _version(_scalar(isakmp.get(F["version"])))
            responder_spi = _scalar(isakmp.get(F["responder_spi"])) or ""
            flag_r = _values(isakmp, F["flag_response"])
            proposals = []
            for node in _dicts_with(isakmp, F["proposal_protocol"]):
                protocol = iana.PROTOCOL_IDS.get(_int(_scalar(node[F["proposal_protocol"]])) or -1, "Unknown")
                if version == "IKEv2":
                    proposals.append(_parse_v2_proposal(node, protocol))
                elif version == "IKEv1":
                    proposals.append(_parse_v1_proposal(node, protocol))
            messages.append(IkeMessage(
                frame_number=_int(_scalar(frame.get("frame.number"))),
                version=version,
                exchange_type=_int(_scalar(isakmp.get(F["exchange_type"]))),
                is_response=(flag_r[0] == "1") if flag_r else None,
                responder_spi_set=bool(responder_spi.replace(":", "").strip("0")),
                proposals=proposals,
                notify_types=_ints(isakmp, F["notify_type"]),
                payload_types=_ints(isakmp, F["payload_type"]),
                auth_methods=_ints(isakmp, F["auth_method"]),
                ports=(_int(_scalar(udp.get("udp.srcport"))), _int(_scalar(udp.get("udp.dstport")))),
                length=_int(_scalar(isakmp.get(F["length"]))),
                timestamp=_float(_scalar(frame.get("frame.time_epoch"))),
            ))
    return messages


# --- derived observations ---------------------------------------------------

def ike_version(messages: list[IkeMessage]) -> dict:
    if not messages:
        return unavailable("No IKE/ISAKMP messages were found in the capture")
    versions = Counter(message.version for message in messages if message.version)
    if not versions:
        return unavailable(f"{len(messages)} ISAKMP message(s) were found but none carried a recognised version")
    evidence = [f"{count} message(s) carry an {version} header (ISAKMP version {version[-1]}.0)" for version, count in sorted(versions.items())]
    if len(versions) == 1:
        return observation(next(iter(versions)), OBSERVED, evidence)
    return observation("Mixed (IKEv1 and IKEv2)", OBSERVED, evidence)


def exchange_types(messages: list[IkeMessage]) -> dict:
    names = Counter(message.exchange_name for message in messages)
    if not names:
        return unavailable("No IKE exchange was observed")
    return observation(sorted(names), OBSERVED, [f"{name}: {count} message(s)" for name, count in sorted(names.items())])


def _proposals(messages: list[IkeMessage], protocols: tuple[str, ...]) -> tuple[list[Proposal], list[Proposal]]:
    selected = [p for m in messages if m.carries_selection for p in m.proposals if p.protocol in protocols]
    offered: dict[tuple, Proposal] = {}
    for message in messages:
        if not message.carries_selection:
            for proposal in message.proposals:
                if proposal.protocol in protocols:
                    offered.setdefault(proposal.signature(), proposal)
    return selected, list(offered.values())


def _negotiated(messages: list[IkeMessage], getter: Callable[[Proposal], list], label: str, protocols: tuple[str, ...] = ("IKE",), scope: str | None = SCOPE_NOTE) -> dict:
    selected, offered = _proposals(messages, protocols)
    scope_evidence = [scope] if scope else []
    chosen = [value for proposal in selected for value in getter(proposal)]
    if chosen:
        counts = Counter(chosen)
        value, count = counts.most_common(1)[0]
        if len(counts) == 1:
            return observation(value, OBSERVED, [f"Responder-selected proposal in {len(selected)} message(s) specifies {label} {value}", *scope_evidence])
        others = ", ".join(f"{v} ({c})" for v, c in counts.most_common())
        return observation(value, OBSERVED_MAJORITY, [f"Responder selections disagree across rekeys or sessions: {others}", *scope_evidence])
    if not offered:
        return unavailable(f"No {label} was visible in a cleartext SA proposal")
    offered_values = sorted({str(value) for proposal in offered for value in getter(proposal)})
    if not offered_values:
        return unavailable(f"Visible SA proposals do not carry a {label} attribute")
    if any(NOTIFY_NO_PROPOSAL_CHOSEN in message.notify_types for message in messages):
        return unavailable(f"The responder rejected the offer (NO_PROPOSAL_CHOSEN); offered {label}: {', '.join(offered_values)}")
    if len(offered) == 1 and len(getter(offered[0])) == 1:
        return observation(getter(offered[0])[0], INFERRED, [
            f"The initiator offered a single proposal with {label} {offered_values[0]}; the responder's reply was not captured, so the selection is inferred",
            *scope_evidence,
        ])
    return unavailable(f"The initiator offered several {label} options ({', '.join(offered_values)}); the responder's selection was not captured")


def cryptography(messages: list[IkeMessage]) -> dict:
    return {
        "scope": "IKE SA" if any(m.proposals for m in messages) else UNKNOWN,
        "encryption_algorithm": _negotiated(messages, lambda p: p.encryption, "encryption"),
        "integrity_algorithm": _negotiated(messages, lambda p: p.integrity, "integrity"),
        "prf_algorithm": _negotiated(messages, lambda p: p.prf, "PRF"),
        "authentication_method": authentication_method(messages),
        "dh_group": _negotiated(messages, lambda p: p.dh, "DH group"),
        "pfs": pfs(messages),
    }


def authentication_method(messages: list[IkeMessage]) -> dict:
    v1 = _negotiated(messages, lambda p: p.authentication, "authentication method", scope=None)
    if v1["value"] != UNKNOWN:
        return v1
    methods = Counter(iana.lookup(iana.IKEV2_AUTH_METHODS, method, "Auth method") for m in messages if m.version == "IKEv2" for method in m.auth_methods)
    if methods:
        value, _ = methods.most_common(1)[0]
        return observation(value, OBSERVED if len(methods) == 1 else OBSERVED_MAJORITY, [f"AUTH payload method {name}: {count} message(s)" for name, count in methods.items()])
    if any(m.version == "IKEv2" for m in messages):
        return unavailable("IKEv2 carries the authentication method in the encrypted IKE_AUTH exchange")
    return v1


def pfs(messages: list[IkeMessage]) -> dict:
    """PFS is decided only from child SA negotiation, which is normally encrypted."""
    without_ke: list[str] = []
    for message in messages:
        child = [p for p in message.proposals if p.protocol in ("ESP", "AH")]
        groups = sorted({name for p in child for name, group in zip(p.dh, p.dh_ids) if group != 0})
        rekey_ke = message.version == "IKEv2" and message.exchange_type == 36 and IKEV2_KE_PAYLOAD in message.payload_types
        if groups or rekey_ke:
            detail = f"key exchange {', '.join(groups)}" if groups else "a KE payload"
            return observation(True, OBSERVED, [f"{message.exchange_name} child SA negotiation includes {detail}"])
        # IKEv1 Quick Mode and IKEv2 CREATE_CHILD_SA must carry a key exchange when PFS is on.
        # IKE_AUTH is not conclusive: implementations such as strongSwan strip KE transforms there.
        if child and (message.version == "IKEv1" and message.exchange_type == 32 or message.version == "IKEv2" and message.exchange_type == 36):
            without_ke.append(message.exchange_name)
    if without_ke:
        return observation(False, OBSERVED, [f"{name} child SA negotiation carries no key exchange" for name in sorted(set(without_ke))])
    evidence = ["The IKE SA DH group alone does not show whether child SAs use PFS"]
    if any(m.version == "IKEv2" for m in messages):
        evidence.insert(0, "IKEv2 child SA proposals and CREATE_CHILD_SA key exchanges are inside encrypted messages")
    if any(m.version == "IKEv1" for m in messages):
        evidence.insert(0, "IKEv1 Quick Mode, which carries the PFS group, is encrypted")
    if not messages:
        evidence = ["No IKE negotiation was captured"]
    return unavailable(*evidence)


def sa_lifetime(messages: list[IkeMessage]) -> dict:
    child = _negotiated(messages, lambda p: p.lifetime_seconds, "lifetime (seconds)", protocols=("ESP", "AH"), scope=None)
    if child["value"] != UNKNOWN:
        child["evidence"].append("Child (IPsec) SA lifetime from a visible phase-2 proposal")
        return child
    ike_sa = _negotiated(messages, lambda p: p.lifetime_seconds, "lifetime (seconds)", scope=None)
    if ike_sa["value"] != UNKNOWN:
        ike_sa["evidence"].append("IKE SA (phase 1) lifetime; the IPsec SA lifetime is set in encrypted Quick Mode")
        return ike_sa
    if any(m.version == "IKEv2" for m in messages):
        return unavailable("IKEv2 does not negotiate SA lifetimes on the wire (RFC 7296 section 2.8); each peer applies local policy")
    return ike_sa


def mode(messages: list[IkeMessage]) -> dict | None:
    """Mode evidence from IKE itself; only present when the negotiation is visible."""
    selected, offered = _proposals(messages, ("ESP", "AH"))
    modes = Counter(value for proposal in (selected or offered) for value in proposal.encapsulation_modes)
    if len(modes) == 1:
        value = next(iter(modes))
        return observation(value, OBSERVED, [f"IKEv1 phase-2 proposal specifies {value} encapsulation mode"])
    if any(iana.NOTIFY_USE_TRANSPORT_MODE in m.notify_types for m in messages):
        return observation("Transport", OBSERVED, ["USE_TRANSPORT_MODE notification observed in the IKEv2 exchange"])
    return None


def proposal_summary(messages: list[IkeMessage]) -> dict:
    selected, offered = _proposals(messages, ("IKE", "ESP", "AH"))
    unique_selected = {p.signature(): p for p in selected}
    return {
        "selected": [p.as_dict() for p in unique_selected.values()],
        "offered": [p.as_dict() for p in offered],
    }
