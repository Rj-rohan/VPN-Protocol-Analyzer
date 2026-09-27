# Security rules and compliance profiles

Two independent views of the same extracted configuration:

- **Security rules** say *what is risky*. Fourteen fixed, explainable rules feed the Project Security Assessment Score.
- **Compliance profiles** say *whether it meets a named standard*. These are editable JSON control lists (NIST SP 800-77r1, CNSA/RFC 9206, and your own).

Both only use values that carry a source label. A rule or control never treats `Unknown` as pass or fail.

## Security rules

Code: `backend/app/security/rules.py`. Every finding carries a rule ID, condition, severity, evidence, impact, recommendation and `source` (`observed`, `inferred` or `predicted`).

| Rule | Severity | Title | Triggers when | Source |
|---|---|---|---|---|
| PROTO-001 | High | Legacy IKE version | IKEv1 observed | observed |
| PROTO-002 | High | IKEv1 Aggressive Mode | Aggressive Mode exchange observed | observed |
| CRYPTO-001 | High | Weak or legacy DH group | DH group 1, 2, 5, 22 or 25 | observed |
| CRYPTO-002 | High | Legacy integrity algorithm | Integrity contains SHA-1 or MD5 | observed |
| CRYPTO-003 | High | PFS disabled | PFS observed or inferred off | observed / inferred |
| CRYPTO-004 | Critical | Weak cipher configuration | DES, 3DES, NULL, RC4 or Blowfish negotiated | observed |
| CRYPTO-005 | Critical | Payload not encrypted | ESP-NULL decodes, or AH without ESP | inferred |
| CRYPTO-006 | Medium | 64-bit block ESP cipher suspected | AI cipher inference says 3DES/Blowfish with confidence ≥ 0.8 | predicted |
| SA-001 | High | Replay protection disabled | Replay protection observed disabled | observed |
| SA-002 | Medium | Excessive SA lifetime | Lifetime above 86,400 s | observed / inferred |
| CONFIG-001 | Medium | Suspicious transform combination | AEAD plus a separate integrity transform, or non-AEAD with integrity NONE | observed |
| META-001 | Low | Endpoint addresses exposed | Transport mode observed, or predicted with confidence ≥ 0.8 | observed / predicted |
| META-002 | Low | Traffic pattern metadata exposure | 20 or more ESP/AH packets with varying sizes (no TFC padding) | observed |
| OBS-001 | Low | Security parameters not observable | Required parameters are hidden in encryption | — |

### Project Security Assessment Score

```
score = max(0, 100 − 30·Critical − 20·High − 10·Medium − 5·Low)
```

| Risk | When |
|---|---|
| Critical | Any Critical finding, or score < 40 |
| High | Any High finding, or score < 70 |
| Medium | Any Medium finding, or score < 85 |
| Low | Otherwise |

This is a transparent project heuristic, not an official rating. The formula and thresholds are returned with every analysis (`security.assessment.methodology`) and printed in both reports.

## Compliance profiles

Code: `backend/app/compliance/engine.py`. Built-in profiles are in `backend/app/compliance/profiles/`. Extra profiles load from `COMPLIANCE_PROFILE_DIR`. The dashboard and the executive report use `DEFAULT_COMPLIANCE_PROFILE` (default `nist-sp-800-77r1`).

### Built-in profiles

**`nist-sp-800-77r1`: NIST SP 800-77 Rev. 1** (default)

| Control | Severity | Requirement | Check |
|---|---|---|---|
| NIST-01 | High | IKEv2 in use | `ike_version equals IKEv2` |
| NIST-02 | High | AES for the IKE SA | `ike_encryption matches ^AES-` |
| NIST-03 | Medium | SHA-2 or AEAD integrity | `ike_integrity matches AEAD\|SHA2` |
| NIST-04 | Medium | SHA-2 PRF (IKEv2 only) | `ike_prf matches SHA2` |
| NIST-05 | High | DH ≥ 2048-bit MODP or ECP | `dh_group_number in [14–21, 31, 32]` |
| NIST-06 | Medium | Perfect Forward Secrecy | `pfs is_true` |
| NIST-07 | Low | IKE SA lifetime ≤ 24 h | `ike_lifetime_or_rekey_seconds max 86400` |
| NIST-08 | Critical | Payload confidentiality | `payload_encrypted is_true` |
| NIST-09 | High | Approved ESP cipher family | `esp_cipher_family not_in [64-bit block, NULL]` |
| NIST-10 | High | No IKEv1 Aggressive Mode | `ike_exchanges not_matches Aggressive` |
| NIST-11 | Low | Signature authentication | `authentication not_matches Pre-Shared` |
| NIST-12 | Low | Child SA lifetime ≤ 8 h | `child_rekey_interval_seconds max 28800` |

**`cnsa-rfc9206`: CNSA Suite for IPsec (RFC 9206).** IKEv2; AES-256; PRF HMAC-SHA2-384; AEAD or SHA-384 integrity; DH group 20 (P-384) or 15 (3072-bit); AEAD ESP; PFS; encrypted payload; no pre-shared keys.

**`org-baseline`: example organisational policy.** IKEv2 only; AES-GCM for IKE; group 15, 16, 19, 20, 21 or 31; PFS; tunnel mode; encrypted payload; AEAD ESP; IKE SA lifetime ≤ 8 h.

### Results

| Control status | Meaning |
|---|---|
| `pass` | The value satisfies the check. `basis` says whether it was observed, inferred or predicted |
| `fail` | The value violates the check |
| `unknown` | Not observable in this capture; verify on the endpoint |
| `not_applicable` | The control's `applies_if` precondition does not hold, e.g. NIST-04 on IKEv1 |

| Profile verdict | When |
|---|---|
| **non-compliant** | Any control fails |
| **compliant** | Every applicable control passes |
| **insufficient evidence** | No failures, but at least one control is unknown |

### Writing a profile

Copy `org-baseline.json` into the folder named by `COMPLIANCE_PROFILE_DIR`, change `id`, and edit the controls. No restart is needed. Because stored analyses are re-evaluated on read, the new profile applies to every past analysis too.

```json
{
  "id": "acme-vpn-2026",
  "name": "ACME VPN standard 2026",
  "version": "1",
  "reference": "ACME-SEC-STD-014 §4",
  "description": "Site-to-site IPsec baseline.",
  "disclaimer": "Derived from the internal standard; not an audit.",
  "controls": [
    {"id": "ACME-01", "title": "IKEv2 only", "requirement": "All tunnels use IKEv2.", "severity": "High",
     "check": {"field": "ike_version", "operator": "equals", "value": "IKEv2"},
     "remediation": "Migrate to IKEv2."},
    {"id": "ACME-02", "title": "SHA-2 PRF", "requirement": "IKEv2 PRF is SHA-2.", "severity": "Medium",
     "applies_if": {"field": "ike_version", "operator": "equals", "value": "IKEv2"},
     "check": {"field": "ike_prf", "operator": "matches", "value": "SHA2"},
     "remediation": "Use PRF_HMAC_SHA2_256 or stronger."}
  ]
}
```

**Operators:** `equals`, `not_equals`, `in`, `not_in`, `min`, `max`, `is_true`, `is_false`, `matches`, `not_matches` (the last two are case-insensitive regular expressions).

**Fields:**

| Field | Value |
|---|---|
| `ipsec_detected` | true / false |
| `ike_version` | `IKEv1`, `IKEv2` |
| `ike_exchanges` | Exchange names, e.g. `IKE_SA_INIT, IKE_AUTH` or `Aggressive Mode` |
| `ike_encryption`, `ike_integrity`, `ike_prf` | IANA names, e.g. `AES-256-GCM-16`, `HMAC-SHA2-256-128`, `AEAD` |
| `authentication` | e.g. `Pre-Shared Key`, `RSA Signature` |
| `dh_group`, `dh_group_number` | `DH14 (MODP-2048)` and `14` |
| `ike_key_bits` | Encryption key length |
| `pfs`, `payload_encrypted`, `nat_traversal`, `replay_protection` | true / false |
| `mode` | `Tunnel`, `Transport` (predicted mode is used if nothing was observed) |
| `esp_cipher_family` | Family name from the ESP cipher inference |
| `sa_lifetime_seconds` | Negotiated lifetime (IKEv1) |
| `child_rekey_interval_seconds`, `ike_rekey_interval_seconds` | Measured rekey spacing |
| `ike_lifetime_or_rekey_seconds` | Negotiated lifetime, or else the smaller measured rekey interval |

Profiles are read from disk on every evaluation and validated with pydantic. A file with invalid JSON, an unknown operator or a bad severity is skipped, and the backend log explains why (`Ignoring invalid compliance profile ...`). A profile with the same `id` as a built-in one replaces it. These checks are derived from the referenced guidance; they are not certifications.
