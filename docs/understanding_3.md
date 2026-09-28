# Understanding parts (c), (d), (e) and the deliverables

This document explains, in plain language, what each remaining item of the problem statement means and exactly what this project implemented for it: where the code is and how well it works. Parts (a) and (b) are in [understanding_1.md](understanding_1.md) and [understanding_2.md](understanding_2.md).

---

## How the "AI engine" is designed

Before the item-by-item list, one design idea explains everything that follows:

> **Facts are read. Hidden things are predicted. Every value says which.**

A capture has two kinds of information:

| Kind | Example | How we get it | Label |
|---|---|---|---|
| **Visible** (cleartext) | IKE version, the cipher chosen in IKE_SA_INIT, DH group, SPIs | **Read directly** by the parser: exact, 100% | `observed` |
| **Deducible** by exact reasoning | PFS from the size of rekey messages; lifetime from rekey timing; "payload not encrypted" from ESP-NULL | **Inferred** by rules with shown evidence | `inferred` |
| **Hidden** by encryption | Tunnel or transport; cipher family inside ESP; what app is in the tunnel | **Predicted by AI** from packet sizes and timing | `predicted`, with a confidence |
| **Truly unobservable** | IKEv2 authentication method; whether the receiver enforces replay protection | Reported honestly | `Unknown / Not observable` |

Using AI to "guess" something that is written in cleartext would only add errors. So the AI is used exactly where it adds value: **for what encryption hides**. Judges can see a badge on every value saying which of the four it is.

**Pipeline** (`backend/app/pipeline.py`):

```
 pcap ─► TShark (2 passes) ─► parser: observed + inferred values
                                   │
                                   ├─► AI: mode + ESP cipher (protocol_models.py)
                                   ├─► AI: traffic type        (ml/predict.py)
                                   ├─► 14 security rules + score   (security/)
                                   ├─► compliance profiles          (compliance/)
                                   └─► AI confidence score          (confidence.py)
                                                     │
                                  database ─► dashboard ─► Executive + Technical PDF
```

---

## (c) AI-based protocol identification

| Item | What it means | What we implemented | How it's identified | Accuracy (17 labelled testbed captures) |
|---|---|---|---|---|
| **IPsec protocol** | Is there IPsec, and is it ESP (encrypted) or AH (integrity only)? | `backend/app/packet/features.py` (detection), `esp.py` | IKE headers (UDP 500/4500), ESP (IP protocol 50 or UDP-encapsulated), AH (protocol 51), consistent sequence numbers. Combined into a **detection confidence** with the evidence listed | **100%** (17/17, including the no-IPsec capture) |
| **IKE version** | IKEv1 (old) or IKEv2 (current) | `backend/app/packet/ike.py` | Version field in the ISAKMP header | **100%** |
| **Tunnel mode / transport mode** | Whether the whole packet or only its data is protected (see [understanding_1.md §1](understanding_1.md#1-tunnel-mode-vs-transport-mode)) | `esp.py`, `esp_structure.py`, `ml/protocol_models.py` | 1) **Read directly** for AH and ESP-NULL. 2) **Physical rule:** an inner packet under 28 bytes means transport. 3) **AI (RandomForest)** on inner packet sizes | Observed: **100%** when reported. AI: **92.9% ± 2.6%** cross-validated; 13/14 on the testbed; 98.4% on real phone VPN traffic |
| **Encryption algorithm** | Which cipher protects the data (AES-GCM, AES-CBC, 3DES…) | `ike.py`, `iana.py`, `esp_structure.py` | IKE SA cipher and key length **read** from IKE_SA_INIT. ESP cipher *family* **inferred by AI**, a Bayesian test on the pattern of packet lengths (no training needed) | IKE: **100%**. ESP family: **100%** of 291 samples where it decided (including real WhatsApp and Gmail) |
| **Authentication algorithm** | 1) Integrity algorithm (HMAC-SHA-256…), which proves data wasn't changed; 2) authentication method (pre-shared key vs certificate), which proves who you are | `ike.py` | Integrity and PRF **read** from IKE. Authentication method **read** for IKEv1; for IKEv2 it travels inside the encrypted IKE_AUTH, so it is reported as **not observable** | Integrity: **100%**. Method: IKEv1 only, by protocol design |
| **Key exchange method** | How the two sides agree on keys: IKE version + **Diffie-Hellman group** (+ PFS on rekeys) | `ike.py`, `rekey.py` | DH group **read** from IKE. PFS **inferred** from rekey message size | DH group: **100%**. PFS: **3/3** rekeying captures |
| **Security Association characteristics** | The properties of each agreed SA: its ID (SPI), lifetime, NAT traversal, sequence behaviour, proposals | `features.py`, `rekey.py`, `esp.py` | SPIs **read**. NAT-T **read** (UDP-encapsulated ESP). Lifetime: **read** in IKEv1, **inferred** from rekey intervals in IKEv2. Replay indicators (duplicates, reordering). Offered vs selected proposals | NAT-T **100%**; rekey interval **3/3** |
| **Type of traffic inside ESP** | What the encrypted tunnel carries: Web, Video, VoIP, Email, Chat, ICMP, File-Transfer | `ml/train.py`, `ml/predict.py`, `packet/traffic.py` | **AI (RandomForest)** on 59 statistics of packet sizes, timing, direction, bursts and idle gaps. Trained on 1,490 labelled examples (real apps + lab); tested separately on real phone WhatsApp/Gmail | **81.3% ± 2.1%** on real apps (strict: every capture held out, mean over 5 splits); **86.0%** overall; **100%** (16/16) on the testbed; **5 of 9** real WhatsApp/Gmail phone recordings it never trained on |

**Where you see it in the app:** Analysis → **Protocol details** tab (every value with its source badge and evidence, plus the **AI protocol inference** panel) and the **Traffic analysis** tab.

---

## (d) Security assessment

We built **two independent checks** on the extracted configuration:

- **14 security rules**, which ask *"what is risky?"* and feed the score (`backend/app/security/rules.py`);
- **compliance profiles**, which ask *"does it meet a named standard?"* (`backend/app/compliance/`).

| Item | What it means | What we implemented |
|---|---|---|
| **Cryptographic strength** | Are the algorithms strong enough today? | **CRYPTO-001** weak DH group (1, 2, 5, 22, 25), High. **CRYPTO-002** SHA-1 or MD5 integrity, High. **CRYPTO-004** DES, 3DES, NULL, RC4 or Blowfish, Critical. **CRYPTO-006** 64-bit block cipher detected by AI, Medium |
| **Configuration compliance** | Does the setup follow an official standard or company policy? | **3 profiles:** NIST SP 800-77 Rev. 1 (12 controls), CNSA/RFC 9206 (9 controls, top-secret level), and an editable organisation baseline (8 controls). Each control is **Pass / Fail / Not observable / N/A** with evidence and remediation; the verdict is *compliant*, *non-compliant* or *insufficient evidence*. **Custom profiles** can be added as JSON without code changes |
| **Security Association parameters** | Are the SA settings sensible and consistent? | **CONFIG-001** suspicious transform combinations (e.g. AEAD + a separate integrity algorithm, or no integrity at all). **SA-002** lifetime too long. Offered vs selected proposal comparison |
| **Key lifetime** | How long a key is used before being replaced (shorter is safer) | Read for IKEv1; **inferred from measured rekey intervals** for IKEv2. **SA-002** flags lifetimes over 24 h; **NIST-07** (IKE ≤ 24 h), **NIST-12** (child ≤ 8 h), **ORG-08** |
| **Replay protection** | Does the receiver reject copied or replayed packets? | **SA-001** fires when it is observed disabled. Sequence-number analysis per SPI: strictly increasing, duplicates, out of order. **Honest limit:** senders always number packets, but whether the *receiver* enforces the check can't be seen on the wire, so it is reported as not observable, with the indicators as evidence |
| **Forward secrecy configuration** | Is PFS on, so one stolen key can't unlock all traffic? | PFS **inferred from rekey message size** (3/3 correct). **CRYPTO-003** "PFS disabled", High; **NIST-06**, **CNSA-07**, **ORG-04** |
| **Cipher suite strength** | Is the whole combination strong, not just one algorithm? | **PROTO-001** IKEv1 in use, High. **PROTO-002** IKEv1 Aggressive Mode, High. **CRYPTO-005** payload not encrypted (ESP-NULL or AH only), Critical. The full suite is checked against NIST and CNSA (e.g. CNSA requires AES-256 + SHA-384 + P-384 together) |
| **Metadata exposure** | What an observer learns *without* decrypting | **META-001** transport mode exposes the real IP addresses of the hosts. **META-002** packet sizes and timing reveal the traffic type (proven by our own traffic classifier; the fix is TFC padding). **OBS-001** lists parameters that must be checked on the devices |

**Where you see it:** Analysis → **Security assessment** tab and **Compliance** tab (switch between profiles).

---

## (e) Output

| Item | What we implemented | Where |
|---|---|---|
| **Comprehensive security score** | **Project Security Assessment Score** out of 100: `100 − 30×Critical − 20×High − 10×Medium − 5×Low`. The formula is shown in the app and reports, so it is fully transparent | Security assessment tab, dashboard, both reports |
| **Risk score** | Risk level **Critical / High / Medium / Low**, from the worst finding and the score (e.g. any Critical finding means Critical risk) | Header of every analysis, dashboard risk chart, reports |
| **Traffic analysis** | Predicted traffic type with the probability of each class; packet-size histogram; timeline of bytes up and down per second; rates, bursts and idle time; the model used and its accuracy | **Traffic analysis** tab, technical report |
| **Metadata inference** | Everything learned from sizes and timing alone: mode, ESP cipher family, traffic type, key lifetime and PFS from rekeys, plus what this exposes (META rules) | AI protocol inference panel, Traffic tab, reports |
| **Threat matrix** | One table: **finding × severity × evidence × impact × recommendation** | **Threat matrix** tab |
| **AI confidence score** | A 0–100 score for *how much of this analysis rests on solid evidence*. It averages: detection confidence; how many of 11 key settings are known (observed counts 1.0, inferred 0.8, predicted less); each AI prediction × that model's measured accuracy. Every part is shown with an explanation | Top of the Security assessment tab, dashboard average, both reports |
| **Executive report** | 1–2 page PDF for managers: overall risk, score, key findings in business language, configuration summary, compliance verdicts, top recommendations | Reports tab → Executive |
| **Technical report** | Full PDF for engineers: every parameter with source and evidence, proposals, AI inference, traffic statistics and charts, all findings, AI confidence breakdown, the complete compliance control table, methodology | Reports tab → Technical |

**Optional AI narrative.** If an Anthropic API key is configured, Claude writes the report text from the analysis facts. A grounding check rejects any sentence that names a value the analyzer didn't produce, so it can't invent algorithms or numbers. Without a key, a built-in template writes the text. Each report says which was used.

Code: `backend/app/reports/` (`executive.py`, `technical.py`, `narrative.py`, `llm.py`, `pdf.py`), `backend/app/confidence.py`.

---

## Expected deliverables

| Deliverable | Status | What it is |
|---|---|---|
| **Working software prototype** | ✅ | FastAPI backend + Next.js dashboard + PostgreSQL. Runs locally on Windows or with Docker Compose. Login with roles (admin, analyst, viewer), background analysis, audit log. **141 automated tests** pass |
| **AI classification engine** | ✅ | 3 components: **traffic classifier** (RandomForest, about 79–81% real apps), **mode classifier** (rule + RandomForest, 92.9%), **ESP cipher inference** (Bayesian, 100% when decided). Models are versioned in `data/models/versions/`, and every prediction states its model and accuracy |
| **Interactive dashboard** | ✅ | Pages: Dashboard (charts, recent analyses, compliance overview), Upload, Analyses list, analysis detail (6 tabs), **Live capture**, Users & audit |
| **Security assessment report** | ✅ | Executive and technical PDFs, generated on demand for any analysis |
| **Demonstration video** | ❌ **Pending** | A scene-by-scene script is to be written, then recorded by the team |
| **Technical documentation** | ✅ | `docs/`: architecture, methodology, user guide, API, model card, evaluation, dataset card, deployment, application security, and these three *understanding* guides. Plus the README |
| **Dataset used for training/testing** | ✅ | `python -m app.dataset_export --zip` packages the 17 labelled strongSwan captures, 374 labelled sessions, feature tables with the exact train/test splits, a feature dictionary, a dataset card and SHA-256 checksums. The ISCX raw data is referenced and cited, not redistributed |

---

## Results at a glance (for the judges)

| What | Result |
|---|---|
| IPsec protocol, IKE version, IP version, cipher, integrity, DH group, NAT-T | **100%** on 17 labelled captures |
| Tunnel/transport (AI) | **92.9% ± 2.6%** (98.4% on real phone VPN traffic) |
| ESP cipher family (AI) | **100%** when decided |
| PFS and key lifetime from rekeys | **3/3** |
| Traffic type (AI) | **81.3% ± 2.1%** on real applications (strict evaluation, mean over 5 splits); 100% on the testbed; 5 of 9 real phone WhatsApp/Gmail recordings never trained on |
| Security rules | **No false alarms** on any rule across 17 captures |

**One line:**

> *"Our engine reads every value the cleartext exposes with 100% accuracy, uses AI only for what encryption hides (mode 93%, cipher 100% when decided, traffic type about 79–81% on real apps), labels every value as observed, inferred or predicted, and turns it all into a transparent score, compliance verdicts against NIST and CNSA, a threat matrix, an AI confidence score, and executive and technical reports."*
