# Methodology: what the analyzer can know, and how

An IPsec capture mixes cleartext negotiation with encrypted payload. The analyzer reports what the cleartext proves. For what is hidden, it either reports it as not observable or infers it from structure and says so. It never presents an inference as an observation.

## Source labels

Every extracted value is an `Observation`:

```json
{"value": "AES-256-GCM-16", "source": "observed", "evidence": ["IKE_SA_INIT response frame 2 selected ENCR_AES_GCM_16 (256-bit)"]}
```

| Source | Meaning | Example |
|---|---|---|
| `observed` | Read directly from a cleartext header or the responder's selected proposal | IKEv2 IKE_SA_INIT transforms |
| `observed-majority` | Observed, but messages disagreed; the majority value is shown and the evidence lists the others | Two IKE SAs with different groups |
| `inferred` | Derived deterministically from structure | Mode from ESP-NULL inner headers; PFS from rekey message size |
| `predicted` | ML or Bayesian output, with a confidence | Traffic class; tunnel vs transport from packet sizes |
| `unavailable` | Not observable in this capture; shown as `Unknown / Not observable` | IKEv2 authentication method (inside the encrypted IKE_AUTH) |

## What a capture exposes

| Parameter | IKEv2 | IKEv1 | How |
|---|---|---|---|
| IKE version, exchange types | observed | observed | ISAKMP header |
| IKE SA encryption / integrity / PRF / DH | observed | observed | IKE_SA_INIT (v2); Main/Aggressive Mode SA payload (v1) |
| Authentication method | unavailable (in IKE_AUTH) | observed | v1 SA attribute |
| SA lifetime | inferred from rekeys | observed | v1 life-duration attribute; v2 sends none (RFC 7296 §2.8) |
| PFS | inferred from CREATE_CHILD_SA size | unavailable (Quick Mode encrypted) | see [Rekey inference](#rekey-inference) |
| Mode | inferred (AH / ESP-NULL), else predicted | same | see [Mode](#mode) |
| ESP cipher family | observed if ESP-NULL, else predicted | same | see [ESP cipher inference](#esp-cipher-inference) |
| NAT traversal | observed | observed | UDP-encapsulated ESP (UDP 4500 carrying non-IKE payload) |
| SPIs | observed | observed | ESP/AH headers |
| Replay protection | unavailable | unavailable | Sequence numbers always increase; receiver enforcement is invisible. `replay_indicators` reports progression, duplicates and reordering |
| Payload confidentiality | inferred | inferred | ESP-NULL decodes, or AH without ESP, means cleartext |

**NAT-T requires UDP-encapsulated ESP.** IKE on port 4500 alone is not proof, because MOBIKE implementations such as strongSwan move IKE to 4500 even without a NAT.

## Parser

1. **Pass 1**, `tshark -T fields`: one row per packet with frame number, time, lengths, protocols, addresses, ports, ESP/AH SPI and sequence, and the ESP-NULL next header. The heuristic `esp.enable_null_encryption_decode_heuristic` is on, so ESP-NULL payloads decode.
2. **Pass 2**, `tshark -Y isakmp -T json -J "frame udp isakmp" --no-duplicate-keys`: IKE packets only. Each becomes an `IkeMessage` (exchange, initiator/response flag, message ID, payload types, proposals, notifies, length, time).
3. **Proposal logic.** The responder's single proposal is the *selected* one (`observed`). The initiator's list is the *offered* set, which is used only when it holds exactly one choice (`inferred`).
4. **ESP payload length** for every ESP packet: `udp.length - 16` for UDP-encapsulated ESP, `ip.len - ip.hdr_len - 8` for IPv4, `ipv6.plen - 8` for IPv6.

Field names live in `backend/app/packet/field_map.py` and transform names in `backend/app/packet/iana.py` (IANA IKEv2 and ISAKMP registries).

## Rekey inference

IKEv2 never transmits lifetimes, but rekeys show on the wire:

- A **CREATE_CHILD_SA** exchange followed within 5 s by ESP traffic on new SPIs is a *child SA rekey*. One without new SPIs is an *IKE SA rekey*.
- The spacing between successive rekeys gives `child_rekey_interval_seconds` and `ike_rekey_interval_seconds`. Compliance uses the smaller as an upper bound on the lifetime.
- **PFS.** A child rekey with PFS carries a KE payload whose size is fixed by the DH group seen in IKE_SA_INIT, for example 256 bytes for MODP-2048 or 64 bytes for ECP-256. The encrypted message is therefore larger. The analyzer compares the CREATE_CHILD_SA request length with `150 + (KE + 16) / 2` bytes: above the threshold means PFS on, below means PFS off. The result is labelled `inferred`, with the sizes as evidence.

## AI protocol inference

### ESP cipher inference

Every ESP payload is `IV + ciphertext + ICV`, where the ciphertext (payload + padding + 2-byte trailer) is a multiple of the cipher block size. Each candidate layout therefore allows only certain lengths:

| Family | IV | Block | ICV |
|---|---|---|---|
| AEAD (AES-GCM, ChaCha20-Poly1305) | 8 | 4 | 16 |
| AES-CBC + HMAC-SHA1-96 | 16 | 16 | 12 |
| AES-CBC + HMAC-SHA2-256-128 | 16 | 16 | 16 |
| 64-bit block (3DES, Blowfish) + HMAC-SHA1-96 | 8 | 8 | 12 |

ESP-NULL is not part of the lattice. When most ESP payloads decode as cleartext (TShark's ESP-NULL heuristic), the status is `readable` and the family is stated directly.

For each layout consistent with every observed length, the posterior grows by `log(block / 4)` per distinct length. If *d* distinct lengths all fit a 16-byte grid, a 4-byte-aligned AEAD layout would produce that by chance with probability (1/4)^*d*. With fewer than 4 distinct lengths (constant-size VoIP, ping) the result is `undecided`. AES-128 and AES-256 produce identical sizes, so key length is never inferred.

### Mode

Once the inferred overhead is removed, each packet's inner size is known.

1. **Physical rule.** An inner packet smaller than 28 bytes cannot contain an IPv4 header plus a transport header, which proves transport mode (`method: physical-bound`).
2. **Otherwise a RandomForest** decides from the inner-size distribution. Tunnel mode adds a 20- or 40-byte inner IP header to every packet, which shows most clearly in TCP ACKs (`esp_frac_inner_ack_*`). Traffic features give it context.

Rule META-001 fires on a transport-mode prediction of 0.8 or higher, and is marked `predicted`.

### Traffic classification

See [model-card.md](model-card.md).

## AI Confidence Score

One transparent 0–100 figure for how much of the analysis rests on solid evidence. It is the mean of the components that apply:

| Component | Value |
|---|---|
| IPsec detection | Evidence-weighted detection confidence |
| Configuration evidence coverage | Mean over 11 key parameters of: observed 1.0, observed-majority 0.9, inferred 0.8, predicted mode 0.7 × confidence, not observable 0 |
| Traffic classification | Model probability × the model's cross-validated accuracy |
| Mode inference | Confidence × the mode model's measured accuracy (the physical rule counts as 0.99) |
| ESP cipher inference | Bayesian posterior of the chosen layout |

ML components are discounted by measured accuracy, so a 99%-confident prediction from a 77%-accurate model contributes 0.76. The score is **not a calibrated probability**. The UI and reports show every component with its explanation, so the figure can be traced.

## Detection confidence

IPsec detection combines independent evidence as `1 − Π(1 − w)`:

| Evidence | Weight |
|---|---|
| IKE header present | 0.6 |
| IKE in both directions | 0.3 |
| ESP as IP protocol 50 | 0.6 |
| UDP-encapsulated ESP | 0.4 |
| Increasing ESP sequence numbers | 0.3 |
| AH as IP protocol 51 | 0.6 |

For example, IKE in both directions plus ESP with increasing sequence numbers gives 1 − 0.4·0.7·0.4·0.7 = 0.92. The result lists each piece of evidence it used.
