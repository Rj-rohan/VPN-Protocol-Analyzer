"""TShark field and preference names used by the parser.

Every dissector field the analyzer depends on is declared here so it can be
checked against `tshark -G fields` for the installed Wireshark version. Names
were verified against TShark 4.6.
"""

# One row per packet (`-T fields`), outer headers first (`-E occurrence=f`).
METADATA_FIELDS: dict[str, str] = {
    "frame_number": "frame.number",
    "timestamp": "frame.time_epoch",
    "length": "frame.len",
    "protocols": "frame.protocols",
    "ip_len": "ip.len",
    "ip_hdr_len": "ip.hdr_len",
    "ipv6_plen": "ipv6.plen",
    "udp_length": "udp.length",
    "ip_src": "ip.src",
    "ip_dst": "ip.dst",
    "ipv6_src": "ipv6.src",
    "ipv6_dst": "ipv6.dst",
    "udp_srcport": "udp.srcport",
    "udp_dstport": "udp.dstport",
    "esp_spi": "esp.spi",
    "esp_sequence": "esp.sequence",
    "esp_next_header": "esp.protocol",
    "ah_spi": "ah.spi",
    "ah_sequence": "ah.sequence",
}

# Fields read from the ISAKMP JSON tree (`-Y isakmp -T json`).
IKE_FIELDS: dict[str, str] = {
    "version": "isakmp.version",
    "exchange_type": "isakmp.exchangetype",
    "length": "isakmp.length",
    "flag_response": "isakmp.flag_r",
    "responder_spi": "isakmp.rspi",
    "payload_type": "isakmp.typepayload",
    "proposal_protocol": "isakmp.prop.protoid",
    "notify_type": "isakmp.notify.msgtype",
    "auth_method": "isakmp.auth.method",
    "ke_group": "isakmp.key_exchange.dh_group",
    # IKEv2 transforms (RFC 7296 section 3.3.2)
    "v2_transform_type": "isakmp.tf.type",
    "v2_encr": "isakmp.tf.id.encr",
    "v2_prf": "isakmp.tf.id.prf",
    "v2_integ": "isakmp.tf.id.integ",
    "v2_dh": "isakmp.tf.id.dh",
    "v2_key_length": "isakmp.ike2.attr.key_length",
    # IKEv1 phase-1 attributes (RFC 2409 appendix A)
    "v1_transform_id": "isakmp.trans.id",
    "v1_encryption": "isakmp.ike.attr.encryption_algorithm",
    "v1_key_length": "isakmp.ike.attr.key_length",
    "v1_hash": "isakmp.ike.attr.hash_algorithm",
    "v1_auth": "isakmp.ike.attr.authentication_method",
    "v1_group": "isakmp.ike.attr.group_description",
    "v1_life_type": "isakmp.ike.attr.life_type",
    "v1_life_duration": "isakmp.ike.attr.life_duration",
    # IKEv1 phase-2 (IPsec DOI, RFC 2407) attributes; only visible if Quick Mode is decrypted
    "v1_ipsec_encap_mode": "isakmp.ipsec.attr.encap_mode",
    "v1_ipsec_group": "isakmp.ipsec.attr.group_description",
}

# Dissector preferences passed with `-o`. ESP-NULL traffic can then expose the
# inner header, which is direct evidence for tunnel versus transport mode.
PREFERENCES: dict[str, str] = {
    "esp.enable_null_encryption_decode_heuristic": "TRUE",
}

IKE_JSON_LAYERS = "frame udp isakmp"
IKE_DISPLAY_FILTER = "isakmp"


def required_fields() -> set[str]:
    return set(METADATA_FIELDS.values()) | set(IKE_FIELDS.values())
