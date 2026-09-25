"""IANA registry values for IKE/IPsec negotiation fields.

TShark reports transform and attribute values as numbers. Naming them here keeps
the mapping deterministic and independent of Wireshark display strings.
Sources: IANA "Internet Key Exchange Version 2 (IKEv2) Parameters" and
"Internet Key Exchange (IKE) Attributes" registries.
"""

IKEV1_EXCHANGE_TYPES = {
    1: "Base", 2: "Main Mode (Identity Protection)", 3: "Authentication Only", 4: "Aggressive Mode",
    5: "Informational", 32: "Quick Mode", 33: "New Group Mode",
}
IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME", 43: "IKE_INTERMEDIATE", 44: "IKE_FOLLOWUP_KE",
}

# IKEv2 transform type 1
IKEV2_ENCR = {
    1: "DES-IV64", 2: "DES", 3: "3DES", 4: "RC5", 5: "IDEA", 6: "CAST", 7: "BLOWFISH", 8: "3IDEA",
    9: "DES-IV32", 11: "NULL", 12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8", 15: "AES-CCM-12",
    16: "AES-CCM-16", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16", 21: "NULL-AUTH-AES-GMAC",
    23: "CAMELLIA-CBC", 24: "CAMELLIA-CTR", 25: "CAMELLIA-CCM-8", 26: "CAMELLIA-CCM-12",
    27: "CAMELLIA-CCM-16", 28: "CHACHA20-POLY1305", 29: "AES-CCM-8-IIV", 30: "AES-GCM-16-IIV",
    31: "CHACHA20-POLY1305-IIV",
}
IKEV2_AEAD_ENCR = {14, 15, 16, 18, 19, 20, 25, 26, 27, 28, 29, 30, 31}

# IKEv2 transform type 2
IKEV2_PRF = {
    1: "HMAC-MD5", 2: "HMAC-SHA1", 3: "HMAC-TIGER", 4: "AES128-XCBC", 5: "HMAC-SHA2-256",
    6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512", 8: "AES128-CMAC",
}

# IKEv2 transform type 3
IKEV2_INTEG = {
    0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 3: "DES-MAC", 4: "KPDK-MD5", 5: "AES-XCBC-96",
    6: "HMAC-MD5-128", 7: "HMAC-SHA1-160", 8: "AES-CMAC-96", 9: "AES-128-GMAC", 10: "AES-192-GMAC",
    11: "AES-256-GMAC", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256",
}

# IKEv2 transform type 4 and IKEv1 group description share one numbering.
DH_GROUPS = {
    0: "NONE", 1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072",
    16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192", 19: "ECP-256", 20: "ECP-384", 21: "ECP-521",
    22: "MODP-1024-160", 23: "MODP-2048-224", 24: "MODP-2048-256", 25: "ECP-192", 26: "ECP-224",
    27: "brainpoolP224r1", 28: "brainpoolP256r1", 29: "brainpoolP384r1", 30: "brainpoolP512r1",
    31: "Curve25519", 32: "Curve448", 35: "ML-KEM-512", 36: "ML-KEM-768", 37: "ML-KEM-1024",
}

IKEV2_AUTH_METHODS = {
    1: "RSA Digital Signature", 2: "Shared Key Message Integrity Code", 3: "DSS Digital Signature",
    9: "ECDSA SHA-256 P-256", 10: "ECDSA SHA-384 P-384", 11: "ECDSA SHA-512 P-521",
    12: "Generic Secure Password", 13: "NULL Authentication", 14: "Digital Signature",
}

IKEV1_ENCRYPTION = {
    1: "DES-CBC", 2: "IDEA-CBC", 3: "Blowfish-CBC", 4: "RC5-R16-B64-CBC", 5: "3DES-CBC",
    6: "CAST-CBC", 7: "AES-CBC", 8: "CAMELLIA-CBC",
}
IKEV1_HASH = {1: "HMAC-MD5", 2: "HMAC-SHA1", 3: "HMAC-TIGER", 4: "HMAC-SHA2-256", 5: "HMAC-SHA2-384", 6: "HMAC-SHA2-512"}
IKEV1_AUTH_METHODS = {
    1: "Pre-Shared Key", 2: "DSS Signatures", 3: "RSA Signatures", 4: "Encryption with RSA",
    5: "Revised Encryption with RSA", 9: "ECDSA SHA-256 P-256", 10: "ECDSA SHA-384 P-384",
    11: "ECDSA SHA-512 P-521", 65001: "XAUTH Pre-Shared Key (initiator)",
    65002: "XAUTH Pre-Shared Key (responder)", 65005: "XAUTH RSA Signatures (initiator)",
    65006: "XAUTH RSA Signatures (responder)",
}
IKEV1_LIFE_TYPES = {1: "seconds", 2: "kilobytes"}
IKEV1_ENCAP_MODES = {
    1: "Tunnel", 2: "Transport", 3: "Tunnel", 4: "Transport",  # 3/4: UDP-encapsulated (RFC 3947)
    61443: "Tunnel", 61444: "Transport",  # pre-RFC NAT-T drafts
}

NOTIFY_NAT_DETECTION = {16388, 16389}
NOTIFY_USE_TRANSPORT_MODE = 16391

PROTOCOL_IDS = {1: "IKE", 2: "AH", 3: "ESP"}


def _with_key_length(name: str, key_length: int | None) -> str:
    if key_length is None:
        return name
    family, _, rest = name.partition("-")
    return f"{family}-{key_length}-{rest}" if rest else f"{family}-{key_length}"


def ikev2_encryption_name(transform_id: int, key_length: int | None) -> str:
    name = IKEV2_ENCR.get(transform_id)
    if name is None:
        return f"ENCR transform {transform_id} (unassigned or private)"
    if name.startswith(("AES-", "CAMELLIA-")):
        return _with_key_length(name, key_length)
    return name


def ikev1_encryption_name(value: int, key_length: int | None) -> str:
    name = IKEV1_ENCRYPTION.get(value)
    if name is None:
        return f"Encryption algorithm {value} (unassigned or private)"
    if name.startswith(("AES-", "CAMELLIA-")):
        return _with_key_length(name, key_length)
    return name


def dh_group_name(group: int) -> str:
    if group == 0:
        return "NONE"
    name = DH_GROUPS.get(group)
    return f"DH{group} ({name})" if name else f"DH{group} (unassigned or private)"


def lookup(table: dict[int, str], value: int, label: str) -> str:
    return table.get(value, f"{label} {value} (unassigned or private)")
