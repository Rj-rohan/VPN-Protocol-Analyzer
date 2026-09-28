# Evaluation

The analyzer is evaluated against captures whose true configuration is known, because the testbed that recorded them wrote it down. `python -m app.evaluation` parses every labelled capture in `data/raw/testbed/`, compares each result with its `capture_NNN.json`, and writes `data/processed/evaluation/evaluation_report.{md,json}`.

## Scoring rules

- **An `Unknown` result is a false negative, never a correct answer.** A value is only correct if it was reported and matches.
- **Precision is measured on reported values.** A wrong value costs more than a missing one.
- **Security rules** are scored as TP/FP/TN/FN against the rules the ground truth should trigger (`evaluation.expected_rules`).
- **AI predictions** (mode, ESP cipher) are scored separately from observed values.

## Results on the 17 strongSwan captures (2026-09-26)

Measured with the current models (`combined-20260928T173414`, protocol inference retrained with the WhatsApp phone recordings). Scenarios: IKEv1 and IKEv2; tunnel and transport; IPv4 and IPv6; NAT-T; PFS on and off; AES-GCM, AES-CBC and ESP-NULL; AH; rekeying; mixed traffic; one capture with no IPsec.

| Check | Result |
|---|---|
| IPsec detection, ESP vs AH, IKE version, IP version | 100% (17/17) |
| IKE SA encryption, integrity, DH group, NAT-T | 100% precision, 100% recall (16/16) |
| PRF | 100% precision, 15/15 |
| Mode (observed) | 100% accurate when reported; reported for the 4 AH and ESP-NULL captures |
| Mode (AI predicted) | 92.9% (13/14) |
| ESP cipher family (AI predicted) | 100% correct when decided (7 of 14 decided) |
| Child SA rekey interval (inferred) | 100% (3/3 within 20%); IKE SA rekey interval exact (45 s) |
| PFS | 100% precision, 3/16 recall: inferred correctly on every rekeying capture, not observable otherwise |
| Authentication method | 1/16 (IKEv1 only; IKEv2 carries it encrypted) |
| Rules PROTO-001, CRYPTO-001, 002, 004, 005, 006, META-001 | No false positives or negatives |
| Rule CRYPTO-003 (PFS off) | 1 TP, 6 FN: PFS is invisible without a rekey |
| Traffic classification | **100% (16/16)** |

**The AI mode miss** is capture_009 (ESP-NULL, tunnel), predicted Transport with 0.57 confidence. On ESP-NULL the mode is also *observed* (Tunnel), and the observed value is what the analysis reports. The prediction stays below the 0.8 threshold that META-001 uses, so it has no effect.

## Scenarios 011–017

| Capture | Scenario | What it tests | Result |
|---|---|---|---|
| 011 | IKEv2 tunnel, AH-SHA256 | AH detection; CRYPTO-005 (no confidentiality); NAT-T is "No" because AH cannot be UDP-encapsulated | ✓ |
| 012 | IKEv2 transport, AH-SHA256 | Mode observed from AH; META-001 | ✓ |
| 013 | IKEv2 tunnel + normal traffic | Detection and features restricted to the IPsec flow | ✓ (traffic VoIP, mode predicted Tunnel) |
| 014 | No IPsec, normal traffic | `ipsec_detected=false`; no IPsec findings | ✓ |
| 015 | Rekey every 20 s, PFS MODP-2048 | Child interval 17 s, IKE interval 45 s, PFS inferred **on** | ✓ |
| 016 | Rekey every 20 s, no PFS | Child interval 20 s, PFS inferred **off**, CRYPTO-003 fires | ✓ |
| 017 | Rekey every 20 s, PFS ECP-256 | PFS **on** with a small (64-byte) KE payload | ✓ |

Record and evaluate:

```bat
python testbed\scripts\run_testbed.py --no-build --only capture_011 capture_012 capture_013 capture_014 capture_015 capture_016 capture_017
cd backend
..\.venv\Scripts\python -m pytest tests\test_testbed_captures.py
..\.venv\Scripts\python -m app.evaluation
```

A rekey interval counts as correct within 20% (or 3 s) of the configured timer.

## Automated tests

`backend/tests/` holds 141 tests: unit, API, authorization, parser integration on generated pcaps, rekey and PFS inference, compliance, the confidence score, live capture and dataset export. `test_testbed_captures.py` adds one parametrized test per labelled capture and field when the testbed captures are present.

```bat
cd backend
..\.venv\Scripts\python -m pytest -q
```

## ML evaluation

See [model-card.md](model-card.md). The key figures, each the mean ± spread over 5 different group splits, are **81.3% ± 2.1%** on real-application ISCX traffic (86.0% ± 1.6% over all sources), **92.9% ± 2.6%** for mode inference and **100%** for ESP cipher inference when it decides. On 9 real WhatsApp and Gmail recordings through a phone's IKEv2 VPN, which the traffic model never trained on, 5 of 9 whole captures are classified correctly (low confidence), the mode model is 98.4% right and the cipher inference 100%. A random window split would report 93.1% on ISCX for the same traffic model, which is why this project does not use one.
