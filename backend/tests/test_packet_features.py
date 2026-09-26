from app.packet import iana
from app.packet.features import UNKNOWN, extract_features
from app.packet.field_map import required_fields
from app.packet.ike import parse_messages
from app.packet.tshark import TSharkService


def test_missing_protocol_parameters_are_explicitly_unavailable() -> None:
    result = extract_features([], [])

    assert result["detection"]["ipsec_detected"] is False
    assert result["detection"]["confidence"] == 0.0
    assert result["mode"]["value"] == "Unknown"
    assert result["cryptography"]["encryption_algorithm"]["value"] == UNKNOWN
    assert result["sa"]["nat_traversal"]["value"] == UNKNOWN
    assert result["sa"]["replay_protection"]["value"] == UNKNOWN


def test_ike_version_is_read_from_the_isakmp_header_byte() -> None:
    packets = [
        {"_source": {"layers": {"isakmp": {"isakmp.version": "0x20", "isakmp.exchangetype": "34"}}}},
        {"_source": {"layers": {"isakmp": {"isakmp.version": "0x10", "isakmp.exchangetype": "2"}}}},
    ]
    versions = [message.version for message in parse_messages(packets)]

    assert versions == ["IKEv2", "IKEv1"]


def test_iana_names_include_key_length_and_group_size() -> None:
    assert iana.ikev2_encryption_name(20, 256) == "AES-256-GCM-16"
    assert iana.ikev2_encryption_name(12, 128) == "AES-128-CBC"
    assert iana.ikev2_encryption_name(3, None) == "3DES"
    assert iana.ikev1_encryption_name(5, None) == "3DES-CBC"
    assert iana.dh_group_name(19) == "DH19 (ECP-256)"
    assert iana.dh_group_name(99) == "DH99 (unassigned or private)"


def test_installed_tshark_supports_every_mapped_field() -> None:
    capabilities = TSharkService().capabilities()
    if not capabilities.available or capabilities.fields is None:
        return
    assert required_fields() <= capabilities.fields
