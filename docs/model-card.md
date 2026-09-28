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

**Independent real-world test set (never used to train this model):** 9 recordings of real apps on an Android phone's built-in IKEv2 client through our strongSwan server (`testbed/scripts/record_real_app.py`): 4 WhatsApp (voice call, chat, video call, file transfer) and 5 Gmail. Each is cut into 15 s windows (69 in total), like the ISCX captures.

Why these recordings are a test set rather than training data: adding them to training lowered real-app accuracy from 79.1% to 74.1–74.4% (mean over 8 group splits), with or without windowing. Their classes don't line up with the ISCX training data: a WhatsApp video call is two-way and steady, while ISCX "Video" is one-way streaming; a Gmail session mixes attachment bursts with idle reading. They are used to train the mode model instead, where the label (tunnel) is unambiguous.

### Evaluation protocol

- **5-fold StratifiedGroupKFold, repeated over 5 different random group splits.** Every capture or VPN configuration is held out once per split, and never appears on both sides. The headline figure is the **mean ± standard deviation over splits**; the confidence score uses the mean (`cv_accuracy`).
- **Why repeated.** Some classes rest on very few recordings (ISCX has two e-mail captures). Which recordings land in the same test fold moves accuracy by several points: over 8 splits, ISCX accuracy ranged from 73% to 83% for the *same* model and data. A single split can therefore look better or worse than the model really is.
- **The independent real-world test** is reported per recording (majority vote of its windows) and per window, and, as the analyzer does it, on each whole capture.
- **A 70/15/15 group-level hold-out** within each source is reported alongside.
- **A random window-level split** is reported only to show how much it overstates accuracy (windows of one recording on both sides).

### Results (combined RandomForest, `combined-20260928T183310`)

| Measure | Value |
|---|---|
| Group CV accuracy, **ISCX real apps** | **81.3% ± 2.1%** (worst split 78.4%, best 83.6%) |
| Group CV accuracy, all sources | 86.0% ± 1.6% (macro-F1 0.868 ± 0.016) |
| Group CV accuracy, Linux lab sessions | 100% |
| Group CV accuracy, strongSwan sessions | 98.8% ± 2.6% |
| Random window split, ISCX (leaky, for comparison only) | 93.1% |
| **Real phone apps, whole capture** (as the analyzer classifies an upload) | **5 of 9 (56%)**: WhatsApp chat, voice call and video call, and 2 of 5 Gmail; confidence 21–45% |
| Real phone apps, per 15 s window | 20% of windows; 2 of 9 recordings by window vote |

Over 8 group splits on the same training data, ISCX accuracy averaged 79.1% ± 3.5%. So about **79–81%** is the fair real-app figure; single splits range from 73% to 84%.

RandomForest (CV macro-F1 0.868) and XGBoost (0.864) were effectively tied; RandomForest was selected on mean macro-F1.

Real-application (ISCX) recall per class, first split: Chat 0.97, Video 0.87, VoIP 0.83, File-Transfer 0.72, Email 0.26.

The most important features are the share of 128–256-byte packets, downlink size variation, the largest burst, inter-arrival variation, burst count and the gap between bursts. Together they describe traffic *behaviour*, not the cipher or the addresses.

**History.** An earlier single-split figure of 83.2% on ISCX was the best of several splits, not a typical one. Before that (`combined-20260926T112543`), adding 9 temporal-pattern features and growing the lab from 8 to 17 VPN profiles lifted real-app Video recall from 0.40 to about 0.7–0.9, depending on the split.

### Known limitations

- **Email** has only two ISCX VPN captures. Most email windows are predicted as Chat (35 of 80), because both are sparse, small-packet exchanges. Importing the ISCX non-VPN captures (`python -m app.ml.iscx --include-nonvpn`) adds four more email captures.
- **File-Transfer vs Video.** Buffered streaming fetches large chunks and resembles bulk download (15–16 windows each way).
- **Modern phone apps (domain shift).** On real WhatsApp and Gmail recorded through a phone's IKEv2 VPN, the model gets 5 of 9 whole captures right with low confidence: today's mobile apps behave differently from the 2016 desktop apps in ISCX. More labelled phone recordings per class are needed before they can join training without lowering the ISCX result.
- **ISCX is 2016 OpenVPN traffic** converted to ESP sizes. The timing and direction are real; the ESP framing is computed. Modern applications (QUIC, HTTP/3) may behave differently.
- **Lab traffic comes from generators** (`testbed/scripts/traffic.py`), so the 100% lab figures measure separability of those generators, not real-world accuracy.
- **Out-of-distribution flows** can be misclassified. The previous model missed `capture_010` (ESP-NULL transport mode, 126-byte packets); the current model classifies all 16 IPsec evaluation captures correctly, because the lab sessions now include NULL and transport profiles.
- **Accuracy on a particular organisation's traffic must be measured** with labelled captures from that environment. Add them as sessions (pcap + JSON label) and retrain.

---

## 2. Mode inference (tunnel vs transport)

1. **Physical rule** (`method: physical-bound`). After removing the inferred ESP overhead, an inner packet under 28 bytes cannot hold an IPv4 + transport header, so the mode is transport. Reported confidence 0.99.
2. **Otherwise a RandomForest** trained on lab sessions with known mode, using the 18 ESP-structure features (inner-size percentiles, the share of inner sizes matching a TCP ACK with or without an inner IP header) plus traffic context.

- **Training data:** lab sessions from 17 VPN profiles (GCM, CBC-SHA1/SHA256, 3DES, NULL; tunnel and transport; IPv4 and IPv6; NAT-T), the strongSwan sessions, and the 9 real phone recordings (WhatsApp and Gmail, tunnel) as 15 s windows. ISCX windows are excluded because their ESP framing is synthetic.
- **Evaluation:** 5-fold group CV, repeated over 5 splits, over 434 samples (lab sessions, strongSwan sessions and 69 windows of the 9 real phone recordings) gives **92.9% ± 2.6%** (range 88.7–95.4%); 10 sessions were decided by the physical rule. By source: lab 92.2%, strongSwan 84.7%, **real phone recordings 98.4%** (before they were added, 0 of 4 WhatsApp recordings were predicted Tunnel). The mean is stored as `cv_accuracy` and shown with every prediction.
- **Limitations:** transport mode carrying only large packets gives the rule nothing to work with, so it falls to the RandomForest. Encrypted IPv6-in-IPv4 tunnels are rare in the training data.

## 3. ESP cipher inference

A closed-form Bayesian test over the RFC 4303 length lattice; see [methodology.md](methodology.md#esp-cipher-inference).

- **Families:** AEAD (AES-GCM / ChaCha20-Poly1305); AES-CBC + HMAC-SHA1-96; AES-CBC + HMAC-SHA2-256-128; 64-bit block (3DES/Blowfish) + HMAC-SHA1-96. ESP-NULL is read directly.
- **Abstains** when fewer than 4 distinct ESP lengths are seen (constant-size VoIP or ping).
- **Results:** 100% correct on all 291 decided samples (67%, including every window of the real phone recordings; the rest had too few distinct lengths):

  | Family | Correct / decided | Sessions |
  |---|---|---|
  | AEAD (AES-GCM) | 89 / 89 | 158 |
  | AES-CBC + HMAC-SHA2-256-128 | 113 / 113 | 151 |
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
