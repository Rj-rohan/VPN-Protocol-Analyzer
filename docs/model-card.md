# Model card

The analyzer has three learned or statistical components. None of them sees payload content; they use only packet sizes, timing and direction, which remain visible under encryption.

| Component | Task | Method | Artifact |
|---|---|---|---|
| Traffic classifier | Web / Video / VoIP / Email / Chat / ICMP / File-Transfer | XGBoost or RandomForest, whichever scores higher in cross-validation | `data/models/traffic_classifier_<source>.joblib` |
| Mode inference | Tunnel vs transport | Physical rule, then RandomForest | `data/models/protocol_inference.joblib` |
| ESP cipher inference | Cipher family | Bayesian length lattice (no training) | none, closed-form |

The figures below are for the models trained on 2026-09-26. Retraining rewrites the per-model reports in `data/models/` (`*_report.md`, `*_metrics.json`), which are the authoritative numbers.

---

## 1. Traffic classifier

### Intended use

- Labels the *kind* of traffic inside an IPsec tunnel, so an analyst can tell whether a tunnel carries calls, streaming, bulk transfer or chat.
- Appears in the UI and reports as **predicted**, with probability and the model's measured accuracy.
- **Not for** attributing traffic to a person, blocking traffic automatically, or any decision that needs certainty. The AI Confidence Score discounts it by measured accuracy.

### Inputs

59 flow statistics of the ESP/AH packets: sizes and their percentiles, inter-arrival times, per-direction rates, bursts (packets closer than 5 ms), idle periods (gaps over 1 s), a 6-bin size histogram and temporal pattern measures. The complete list with descriptions is `features/feature_dictionary.csv` in the [dataset package](dataset.md). Nothing depends on addresses, ports or SPIs.

### Training data

| Source | Rows | Groups | What it is |
|---|---|---|---|
| `iscx_vpn_2016_openvpn_converted` | 1,116 | 30 captures | Real application traffic (Skype, Hangouts, Facebook, YouTube, Netflix, Vimeo, Spotify, email, SFTP/FTPS) from ISCX VPN-nonVPN 2016, re-framed as ESP sizes, in 15 s windows |
| `linux_xfrm_netns_capture` | 357 | 17 VPN profiles | Kernel-encrypted ESP between Linux network namespaces (GCM, CBC-SHA1/SHA256, 3DES, NULL; tunnel/transport; IPv4/IPv6; NAT-T), traffic from the project generators |
| `strongswan_testbed_capture` | 17 | 2 scenarios | strongSwan 5.9.8 in Docker |

Total: 1,490 rows in 49 groups.

### Evaluation protocol

- **5-fold StratifiedGroupKFold** over the combined data: every capture or VPN configuration is held out once and never split across train and test. This is the headline figure and the one the confidence score uses (`cv_accuracy`).
- **A 70/15/15 group-level hold-out** within each source, reported alongside.
- **A random window-level split**, reported only to show how much it overstates accuracy (windows of one recording on both sides).

### Results (combined RandomForest, `combined-20260926T150801`)

| Measure | Value |
|---|---|
| Group CV accuracy, all sources | **87.4%** (macro-F1 0.884) |
| Group CV accuracy, ISCX real apps | **83.2%** (macro-F1 0.751) |
| Group CV accuracy, Linux lab sessions | 100% |
| Group CV accuracy, strongSwan sessions | 100% |
| Random window split, ISCX (leaky, for comparison only) | 93.1% |
| Single 70/15/15 hold-out, ISCX part | 46.9% (only 5 test captures; see below) |

RandomForest (CV macro-F1 0.884) was selected over XGBoost (0.873) on cross-validation.

Real-application (ISCX) results per class, group CV:

| Class | Precision | Recall | Captures |
|---|---|---|---|
| Chat | 0.78 | 0.97 | 10 |
| VoIP | 0.97 | 0.83 | 7 |
| Video | 0.90 | 0.87 | 5 |
| File-Transfer | 0.72 | 0.72 | 6 |
| Email | 0.75 | 0.26 | 2 |

The most important features are the share of 128–256-byte packets, downlink size variation, the largest burst, inter-arrival variation, burst count and the gap between bursts. Together they describe traffic *behaviour*, not the cipher or the addresses.

**Why the hold-out figure is lower.** The single hold-out puts only 5 ISCX captures in the test set. One of them is a VoIP call whose windows are mostly predicted as Chat (37 of 49), and that one capture decides the score. Cross-validation holds out every capture once, so it is the stable figure, and it is the one reported and used by the confidence score.

**What changed from the previous model** (`combined-20260926T112543`: ISCX 76.6%, all 79.7%): 9 temporal-pattern features were added (burst bytes, inter-burst gaps, per-second variation, active-second share), and the lab sessions grew from 8 to 17 VPN profiles. Video recall on real apps rose from 0.40 to 0.87.

### Known limitations

- **Email** has only two ISCX VPN captures. Most email windows are predicted as Chat (35 of 80), because both are sparse, small-packet exchanges. Importing the ISCX non-VPN captures (`python -m app.ml.iscx --include-nonvpn`) adds four more email captures.
- **File-Transfer vs Video.** Buffered streaming fetches large chunks and resembles bulk download (15–16 windows each way).
- **ISCX is 2016 OpenVPN traffic** converted to ESP sizes. The timing and direction are real; the ESP framing is computed. Modern applications (QUIC, HTTP/3) may behave differently.
- **Lab traffic comes from generators** (`testbed/scripts/traffic.py`), so the 100% lab figures measure separability of those generators, not real-world accuracy.
- **Out-of-distribution flows** can be misclassified. The previous model missed `capture_010` (ESP-NULL transport mode, 126-byte packets); the current model classifies all 16 IPsec evaluation captures correctly, because the lab sessions now include NULL and transport profiles.
- **Accuracy on a particular organisation's traffic must be measured** with labelled captures from that environment. Add them as sessions (pcap + JSON label) and retrain.

---

## 2. Mode inference (tunnel vs transport)

1. **Physical rule** (`method: physical-bound`). After removing the inferred ESP overhead, an inner packet under 28 bytes cannot hold an IPv4 + transport header, so the mode is transport. Reported confidence 0.99.
2. **Otherwise a RandomForest** trained on lab sessions with known mode, using the 18 ESP-structure features (inner-size percentiles, the share of inner sizes matching a TCP ACK with or without an inner IP header) plus traffic context.

- **Training data:** lab sessions from 17 VPN profiles (GCM, CBC-SHA1/SHA256, 3DES, NULL; tunnel and transport; IPv4 and IPv6; NAT-T). ISCX windows are excluded because their ESP framing is synthetic.
- **Evaluation:** 5-fold group CV by VPN profile over 370 sessions from 19 profiles gives **97.0%** (recall Tunnel 0.98, Transport 0.96). 10 sessions were decided by the physical rule. The accuracy is stored in the artifact as `cv_accuracy` and shown with every prediction.
- **Limitations:** transport mode carrying only large packets gives the rule nothing to work with, so it falls to the RandomForest. Encrypted IPv6-in-IPv4 tunnels are rare in the training data.

## 3. ESP cipher inference

A closed-form Bayesian test over the RFC 4303 length lattice; see [methodology.md](methodology.md#esp-cipher-inference).

- **Families:** AEAD (AES-GCM / ChaCha20-Poly1305); AES-CBC + HMAC-SHA1-96; AES-CBC + HMAC-SHA2-256-128; 64-bit block (3DES/Blowfish) + HMAC-SHA1-96. ESP-NULL is read directly.
- **Abstains** when fewer than 4 distinct ESP lengths are seen (constant-size VoIP or ping).
- **Results:** 100% correct on all 227 decided lab sessions (61% of 370; the rest had too few distinct lengths):

  | Family | Correct / decided | Sessions |
  |---|---|---|
  | AEAD (AES-GCM) | 89 / 89 | 158 |
  | AES-CBC + HMAC-SHA2-256-128 | 49 / 49 | 87 |
  | AES-CBC + HMAC-SHA1-96 | 24 / 24 | 42 |
  | 64-bit block (3DES) + HMAC-SHA1-96 | 24 / 24 | 42 |
  | ESP-NULL (read directly) | 41 / 41 | 41 |
- **Cannot distinguish** AES-128 from AES-256 (identical sizes), or GCM from ChaCha20-Poly1305 (identical framing).

## Ethical considerations

Traffic classification of encrypted tunnels is a form of traffic analysis. The tool is meant for authorised operators assessing their own VPNs. Upload and view actions are audited, analysts see only their own captures, and the tool stores packet metadata, never payloads. The same leakage it measures is reported to the user as rule META-002, with the mitigation (TFC padding).

## Reproduce

```bat
cd backend
..\.venv\Scripts\python -m app.ml.iscx                    :: ISCX captures -> data\processed\iscx_features.csv
..\.venv\Scripts\python -m app.ml.train --source combined :: traffic classifier + report
..\.venv\Scripts\python -m app.ml.protocol_models         :: mode model + cipher inference measurement
```

Seeds are fixed (26160). Every model is archived under `data/models/versions/<version>/` with its metrics, so an earlier model can be restored by copying it back.
