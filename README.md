# IPsec Analyzer

AI-powered IPsec VPN protocol analyzer and security assessment framework for **Smart India Hackathon problem statement 26160**.

An authorized engineer uploads a `.pcap`, and the system:

1. identifies IKE/ESP/AH, the IKE version, cryptographic transforms, DH group, NAT-T, IP version and SPIs;
2. infers SA lifetime and PFS from rekeys, and predicts tunnel/transport mode and the ESP cipher family from encrypted packet lengths;
3. runs an explainable security rule engine and checks compliance with NIST SP 800-77r1, CNSA (RFC 9206) or your own policy;
4. predicts a traffic category (Web, Video, VoIP, Email, Chat, ICMP or File-Transfer) from encrypted-traffic metadata;
5. presents everything in a dashboard with an AI confidence score and executive and technical PDF reports. Captures come from uploads or live capture.

Payloads are never decrypted. Full documentation is in [docs/](docs/README.md).

```
PCAP ─► TShark (2 passes) ─► packet parser ─► structured IPsec features
                                                   │
                        ┌──────────────────────────┴──────────────────────────┐
                        ▼                                                     ▼
              ML traffic classifier                              security rule engine
              (probabilistic, "predicted")                       (deterministic, "observed")
                        └──────────────────────────┬──────────────────────────┘
                                                   ▼
                            structured results (PostgreSQL) ─► dashboard
                                                   ▼
                   optional LLM explanation layer (grounded) ─► PDF reports
```

The parser and rule engine are the only source of observed protocol values. ML results appear beside them, labelled as predictions, and never overwrite them. The LLM only writes explanations, and its text is rejected if it names any value the analyzer did not produce.

## Quick start with Docker

```bash
cp .env.example .env          # set POSTGRES_PASSWORD, JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD
docker compose up --build
```

Open http://localhost:3000 and sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`. API docs are at http://localhost:8000/docs.

## Local development (Windows, cmd)

Prerequisites: Python 3.11, Node 22, PostgreSQL, and Wireshark (for TShark).

```bat
:: one-time: database and dependencies
psql -U postgres -c "CREATE ROLE ipsec LOGIN PASSWORD 'ipsec';" -c "CREATE DATABASE ipsec_analyzer OWNER ipsec;"
python -m venv .venv
.venv\Scripts\python -m pip install -r backend\requirements.txt
cd frontend && npm install && cd ..
```

Create `backend\.env`:

```
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
JWT_SECRET=<python -c "import secrets; print(secrets.token_urlsafe(48))">
ADMIN_EMAIL=admin@ipsec.local
ADMIN_PASSWORD=<a strong password>
```

Create `frontend\.env.local` containing `NEXT_PUBLIC_API_URL=http://localhost:8001`.

```bat
:: terminal 1: backend (migrations run automatically on startup)
cd backend
..\.venv\Scripts\python -m uvicorn app.main:app --reload --port 8001

:: terminal 2: frontend
cd frontend
npm run dev
```

Other users are created on the **Users & audit** page, or with `python -m app.cli create-user someone@org --role analyst`.

## Features

| Area | What it does |
|---|---|
| Upload | Drag-and-drop with progress. Accepts `.pcap`, `.pcapng` and `.cap`, and checks the file signature, not just the extension. Enforces a size limit, stores files under their SHA-256 hash and analyzes them in a background worker. |
| Detection | IPsec, IKE, ESP and AH detected, with an evidence-weighted confidence score and the evidence listed. |
| Protocol | IKEv1 and IKEv2, exchange types, IPv4/IPv6, SPI values, and NAT-T (UDP-encapsulated ESP). |
| Crypto | Encryption, integrity, PRF, DH group, authentication method and SA lifetime from cleartext negotiation. The responder's selection is kept separate from the initiator's offer. |
| Mode | Tunnel or Transport from AH, ESP-NULL or visible IKE negotiation. Otherwise `Unknown`, never guessed. |
| Security | 14 rules, each with a rule ID, condition, severity, evidence, impact and recommendation, plus a transparent Project Security Assessment Score. |
| Traffic ML | RandomForest and XGBoost compared on a group-level split, using metadata only: sizes, timing, direction, bursts. |
| Reports | Executive and technical PDFs (ReportLab). The narrative is deterministic, or comes from the optional grounded LLM layer. |
| Access | JWT authentication, admin/analyst/viewer roles, per-owner isolation, login lockout and an audit log. |
| Compliance | NIST SP 800-77r1, CNSA (RFC 9206) and editable organisation profiles, with Pass, Fail, Not observable or N/A per control. |
| AI inference | Mode and ESP cipher family from packet lengths; SA lifetime and PFS from rekey timing and sizes. |
| AI confidence | A 0–100 score, broken into components, for how much of each analysis rests on solid evidence. |
| Live capture | Record from an interface with dumpcap, with rolling analysis while it runs (admin only). |
| Testbed | Dockerized strongSwan producing labelled captures across 17 scenarios (including AH, rekeying and non-IPsec traffic), plus a WSL netns ESP session recorder. |
| Evaluation | Accuracy, precision and recall, confusion matrix, and TP/FP/TN/FN for each security rule, all against ground truth. |
| Dataset | `python -m app.dataset_export` packages the labelled captures, features, splits, a dataset card and SHA-256 checksums. |

## Every value says where it came from

Each extracted value carries a `source` and an `evidence` list:

| Source | Meaning |
|---|---|
| `observed` | Read directly from a cleartext header or the responder's selected proposal. |
| `observed-majority` | Observed, but different messages disagreed; the majority value is shown and the evidence lists the rest. |
| `inferred` | Derived from structure, for example ESP-NULL inner headers, or an initiator offer that had only one option. |
| `predicted` | ML output only (the traffic category). |
| `unavailable` | Not observable in this capture. Reported as `Unknown / Not observable`. |

What a capture can and cannot show:

- **Cryptographic values describe the IKE SA.** Only IKEv2 IKE_SA_INIT and IKEv1 Main/Aggressive Mode are in cleartext. ESP child SA transforms, PFS, IKEv1 Quick Mode and the IKEv2 authentication method are inside encrypted messages.
- **Mode needs structural evidence.** Encrypted ESP hides the inner header.
- **NAT-T means UDP-encapsulated ESP.** IKE on port 4500 alone is not proof, because MOBIKE implementations such as strongSwan move IKE to 4500 even without a NAT. The first real testbed capture exposed this.
- **Replay protection is not observable.** Senders always increment ESP sequence numbers, and receiver enforcement is invisible on the wire. `replay_indicators` reports sequence progression, duplicates and reordering.
- **IKEv2 does not send SA lifetimes** (RFC 7296 §2.8). When the capture contains rekeys, both lifetime and PFS are **inferred** instead:
  - **Lifetime:** a CREATE_CHILD_SA request followed by new ESP SPIs is a child rekey; one without new SPIs is an IKE SA rekey. The spacing between rekeys gives `child_rekey_interval_seconds` and `ike_rekey_interval_seconds`.
  - **PFS:** a child rekey with PFS carries a KE payload whose size is fixed by the DH group seen in IKE_SA_INIT (for example 256 bytes for MODP-2048). The encrypted message length therefore shows whether PFS is on.

## Parser design

TShark runs twice per capture, always with an argument list and never through a shell:

1. `-T fields` gives one compact row per packet (addresses, ports, ESP/AH SPI and sequence numbers, and ESP-NULL next header).
2. `-Y isakmp -T json --no-duplicate-keys` covers IKE packets only. Without that flag TShark's JSON repeats keys, and JSON parsers silently keep only the last one.

Every dissector field lives in `backend/app/packet/field_map.py` and is checked against `tshark -G fields` at startup; `/health` reports any missing fields. Transform IDs are named from the IANA registries in `backend/app/packet/iana.py`. Truncated captures are analyzed as far as they can be read, with a warning, and non-captures are rejected.

## Security assessment

| Rule | Severity | Triggers when |
|---|---|---|
| PROTO-001 | High | IKEv1 observed |
| PROTO-002 | High | IKEv1 Aggressive Mode observed |
| CRYPTO-001 | High | Weak DH group (1, 2, 5, 22, 25) |
| CRYPTO-002 | High | SHA-1 or MD5 integrity |
| CRYPTO-003 | High | PFS observed disabled |
| CRYPTO-004 | Critical | DES, 3DES, NULL, RC4 or Blowfish encryption |
| CRYPTO-005 | Critical | Payload not encrypted (ESP-NULL decodes, or AH only) |
| CRYPTO-006 | Medium | ESP packet lengths indicate a 64-bit block cipher (3DES/Blowfish), predicted with confidence ≥ 0.8 |
| SA-001 | High | Replay protection observed disabled |
| SA-002 | Medium | SA lifetime above 86,400 s |
| CONFIG-001 | Medium | AEAD cipher with a separate integrity transform, or a non-AEAD cipher with integrity NONE |
| META-001 | Low | Transport mode exposes the endpoints' real addresses |
| META-002 | Low | Packet sizes and timing expose the traffic pattern (no TFC padding) |
| OBS-001 | Low | Security parameters not observable; confirm on the endpoints |

**Project Security Assessment Score** = max(0, 100 − 30·Critical − 20·High − 10·Medium − 5·Low). Risk is Critical for any Critical finding or a score below 40, High for any High finding or a score below 70, Medium for any Medium finding or a score below 85, and Low otherwise. This is a transparent project heuristic, not an official security rating or standard.

## Traffic classification (ML)

```bat
cd backend
..\.venv\Scripts\python -m app.ml.iscx                       :: ISCX real-app captures -> features
..\.venv\Scripts\python -m app.ml.train --source combined    :: lab sessions + ISCX (the active model)
..\.venv\Scripts\python -m app.ml.train --source sessions    :: lab sessions only
..\.venv\Scripts\python -m app.ml.train --source synthetic   :: supplied 2,000-row CSV (scaffolding)
```

- **Leakage-safe evaluation.** 5-fold group cross-validation, in which every capture or VPN configuration is held out once. A 70/15/15 group-level hold-out is reported alongside it. No group ever appears on both sides.
- **Model comparison.** RandomForest and XGBoost are both trained, and the better one on cross-validated macro-F1 is kept. Its metrics go to `data/models/traffic_classifier_<source>_report.md`, and every model is archived in `data/models/versions/`.
- **Model preference.** Prediction uses the combined model when it exists. Every prediction says which data trained its model and what its cross-validated accuracy was.
- **Training data.** 1,490 rows in 49 groups:
  - 1,116 real-app windows from 30 ISCX VPN captures;
  - 357 lab sessions recorded without Docker by `testbed/scripts/netns_sessions.py` (kernel ESP between network namespaces, 17 profiles: GCM, CBC-SHA1/SHA256, 3DES, NULL, tunnel/transport, IPv4/IPv6, NAT-T);
  - 17 strongSwan sessions.

Results:

| Model | On its own data | Real apps (ISCX 2016, whole captures held out) |
|---|---|---|
| Synthetic CSV model (XGBoost) | 98.7% (15 unseen config groups) | not measured; it scored **0%** on real strongSwan captures, because the synthetic statistics look nothing like real traffic (VoIP at 0.1 packets/s instead of about 100) |
| Lab-session model | 100% (unseen VPN profiles) | 48.6% (never trained on real apps) |
| **Combined model (RandomForest, active)** | 100% lab and strongSwan sessions (group CV) | **83.2%** (5-fold group CV over 30 captures, 1,116 windows) |

- **Overall:** 87.4% cross-validated accuracy, macro-F1 0.884. The same model scores 93.1% on ISCX under a random window split, which is how many papers report it; that split leaks windows of one recording into both sides.
- **Real-app recall per class:** Chat 97%, Video 87%, VoIP 83%, File-Transfer 72%, Email 26%.
- **Email is weak** because the ISCX VPN set has only two email captures, and email windows look like chat (sparse, small packets). `python -m app.ml.iscx --include-nonvpn` adds the non-VPN captures, including four more email captures.
- **Earlier model:** the previous combined model scored 76.6% on real apps (Video 40%). Adding temporal-pattern features and 9 more lab profiles raised it to 83.2%.

Details and per-class precision are in [docs/model-card.md](docs/model-card.md).

**Real applications (ISCX VPN-nonVPN 2016).** `python -m app.ml.iscx` imports this public dataset of real app traffic captured through OpenVPN: Skype, Facebook and Hangouts calls and chat, YouTube, Vimeo, Netflix and Spotify, email, SFTP and FTPS. It keeps the tunnel flow and converts each packet to its ESP (AES-GCM, tunnel-mode) size while preserving real timing and direction. It splits each capture into 15-second windows, and the label comes from the filename. Then `python -m app.ml.train --source combined` trains on the lab sessions and the ISCX windows together, splits within each source, and reports held-out accuracy per source. Every model is archived in `data/models/versions/`. Download it from https://www.unb.ca/cic/datasets/vpn.html; the capture archives go in `data/raw/iscx2016/`. By default only the `vpn_*` captures are imported; `--include-nonvpn` also imports the non-VPN ones, wrapped as ESP the same way and reported as a separate source. Citation: G. Draper-Gil, A. H. Lashkari, M. Mamun, A. A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", ICISSP 2016, pp. 407–414.

The most important features are the share of 128–256-byte packets, downlink size variation, the largest burst, timing variation, burst count and the gap between bursts, so the model recognises traffic behaviour whatever the cipher, mode or IP version.

**Caveat:** the lab scores come from the project's own traffic generators (`testbed/scripts/traffic.py`). The ISCX score (83.2%) is the real-application figure, but that dataset is from 2016 and was converted from OpenVPN. Accuracy on a particular organisation's traffic still has to be measured with labelled captures from that environment. Adding such captures and retraining is supported.

## Configuration compliance

Every analysis is checked against compliance profiles: JSON files of controls, in `backend/app/compliance/profiles/`, plus any in `COMPLIANCE_PROFILE_DIR`.

| Profile | Basis |
|---|---|
| `nist-sp-800-77r1` (default) | NIST SP 800-77 Rev. 1 IPsec VPN guidance: IKEv2, AES, SHA-2, DH at least 2048-bit or ECP, PFS, bounded lifetime, encrypted payload, no Aggressive Mode, signature authentication |
| `cnsa-rfc9206` | CNSA Suite for IPsec (RFC 9206): AES-256, SHA-384, P-384 or DH-3072, no pre-shared keys |
| `org-baseline` | An editable example of an organisation's own policy |

Each control gets a result:
- **Pass or Fail**, with its basis (observed, inferred, or AI-predicted) and the evidence;
- **Not observable**, when the value is hidden in encryption;
- **N/A**, when a precondition doesn't hold (for example IKEv2-only checks on IKEv1).

A profile is **compliant** only when every applicable control passes on evidence. Any failure makes it **non-compliant**. Otherwise it's **insufficient evidence**, meaning the remaining controls must be verified on the endpoints.

Results appear in the analysis **Compliance** tab, on the dashboard and in both reports. `GET /api/analyses/{id}/compliance` re-evaluates stored analyses, so new or edited profiles apply retroactively. These are checks derived from the referenced guidance, not certifications.

## AI protocol inference (mode and ESP cipher from encrypted packet lengths)

`python -m app.ml.protocol_models` trains and measures it. Results appear as **predicted, with confidence and evidence**, next to (never instead of) observed values. The two parts:

- **ESP cipher family: Bayesian length-lattice inference.** It needs no training. Every ESP payload is IV + ciphertext + ICV, with the ciphertext padded to the cipher's block, so the set of distinct lengths fits some layouts and not others. If *d* distinct lengths all sit on a 16-byte grid, a 4-byte-aligned AEAD layout would produce that by chance with probability (1/4)^*d*.
  - **Families:** AEAD (AES-GCM or ChaCha20-Poly1305); AES-CBC with HMAC-SHA1-96 or HMAC-SHA2-256-128; 64-bit block ciphers (3DES or Blowfish, flagged by rule CRYPTO-006); and ESP-NULL.
  - **When it abstains:** with fewer than 4 distinct lengths (constant-size VoIP, video or ping) it reports "undecided".
  - **Key length** (AES-128 vs AES-256) is never inferred, because both produce identical packet sizes.
- **Tunnel vs transport mode: a physical rule, then a RandomForest.** Once the cipher overhead is removed, each packet's inner size is known. An inner packet under 28 bytes can't hold an IPv4 header plus a transport header, which proves transport mode. Otherwise a RandomForest decides from the inner-size distribution (tunnel mode adds a 20- or 40-byte inner header to every packet, which shows most clearly in TCP ACKs) plus traffic context. Rule META-001 also fires on a transport-mode prediction with confidence of 0.8 or higher, marked as predicted.
- **Training data:** labelled lab sessions from 17 VPN profiles (`netns_sessions.py`: GCM, CBC-SHA1/SHA256, 3DES, NULL, tunnel/transport, IPv4/IPv6, NAT-T). ISCX windows are excluded because their ESP framing is synthetic.
- **Results** (group CV by VPN profile, 370 sessions from 19 profiles):
  - Mode is **97.0%** accurate (Tunnel recall 0.98, Transport 0.96).
  - ESP cipher family is **100%** correct on all 227 sessions where it decided (61%), across AEAD, CBC-SHA1, CBC-SHA256, 3DES and NULL.

## Live capture

The **Live capture** page (admin only by default: `LIVE_CAPTURE_ROLES`) records from a network interface of the analyzer host using `dumpcap`.
- **Setup:** choose an interface from the list `dumpcap -D` reports, then the "IPsec only" or "All traffic" filter preset and a duration (limits `LIVE_CAPTURE_MAX_SECONDS` and `LIVE_CAPTURE_MAX_MEGABYTES`).
- **While it runs:** the capture is re-analysed every few seconds, showing packets, IPsec detection, IKE version, ESP rate, SPIs and the current score.
- **When it ends or is stopped:** it's stored like an upload and fully analysed.
- **Safety:** one capture at a time, no shell, and only preset filters; starts, stops and completions are audited.
- **In Docker,** live capture needs the backend to use `network_mode: host` and `cap_add: [NET_RAW, NET_ADMIN]`.

## Evaluation

```bat
python testbed\scripts\run_testbed.py              :: 17 labelled strongSwan captures -> data\raw\testbed
cd backend
..\.venv\Scripts\python -m app.evaluation          :: -> data\processed\evaluation\evaluation_report.md
..\.venv\Scripts\python -m pytest                  :: unit, API, parser-integration and ground-truth tests (141)
```

Results on the 17 real captures: IKEv1/IKEv2, tunnel/transport, IPv4/IPv6, NAT-T, PFS on/off, AES-GCM/CBC, ESP-NULL, AH, rekeying, mixed traffic, and one capture with no IPsec.

| Check | Result |
|---|---|
| IPsec detection, ESP vs AH, IKE version, IP version | 100% (17/17, including the no-IPsec capture) |
| Encryption, integrity, PRF, DH group, NAT-T | 100% precision, 100% recall (16/16) |
| Mode (observed) | 100% accurate when reported: AH and ESP-NULL captures, 4/16. Encrypted ESP is correctly `Unknown` |
| Mode (AI predicted) | 92.9% (13/14); the one miss is an ESP-NULL capture whose mode is also observed directly, so the displayed value is right |
| ESP cipher family (AI) | 100% when decided (7/14); constant-size traffic is left undecided |
| Rekey interval (inferred) | 100% (3/3 within 20% of the configured timer; IKE rekey exact) |
| PFS | 100% precision; inferred correctly on all 3 rekeying captures (on, off, and on with ECP-256). Without a rekey it is not observable |
| IKEv2 authentication | Not observable by design (inside encrypted IKE_AUTH); IKEv1 observed |
| Rules PROTO-001, CRYPTO-001/002/004/005/006, META-001 | No false positives or false negatives |
| Rule CRYPTO-003 (PFS off) | 1 TP, 0 FP, 6 FN: the misses are PFS-off captures without a rekey, where PFS is invisible |
| Traffic classification (combined model) | **100% (16/16)** |

Details are in [docs/evaluation.md](docs/evaluation.md).

## Testbed

`testbed/` runs two strongSwan 5.9 peers in Docker. See `testbed/README.md` for the 17 scenarios (011–017 add AH, mixed and non-IPsec traffic, and rekeying with and without PFS; results in [docs/evaluation.md](docs/evaluation.md)), the ground-truth format (`capture_NNN.pcap` + `capture_NNN.json`) and the `--dataset` mode that records labelled ML sessions.

## API

| Method and path | Role | Purpose |
|---|---|---|
| `POST /api/auth/login` | any | Get a bearer token (lockout after 5 failures) |
| `GET /api/auth/me` | signed in | Current user |
| `GET/POST /api/auth/users`, `PATCH /api/auth/users/{id}` | admin | Manage users |
| `POST /api/captures/upload` | analyst, admin | Upload a capture (202, analysis queued) |
| `GET /api/analyses` | signed in | List with `risk`, `status` and paging filters |
| `GET /api/analyses/{id}` | owner, viewer, admin | Full structured result |
| `GET /api/analyses/{id}/status` | owner, viewer, admin | Progress polling |
| `DELETE /api/analyses/{id}` | owner, admin | Delete the analysis, its reports and the stored capture |
| `GET /api/dashboard/summary` | signed in | Dashboard statistics |
| `GET /api/analyses/{id}/narrative?llm=` | owner, viewer, admin | Executive and technical explanation |
| `POST /api/analyses/{id}/reports` | owner, viewer, admin | Generate an executive or technical PDF |
| `GET /api/reports/{id}/download` | owner, viewer, admin | Download a PDF |
| `GET /api/audit` | admin | Audit log |
| `GET /api/compliance/profiles` | signed in | Available compliance profiles |
| `GET /api/analyses/{id}/compliance?profile=` | owner, viewer, admin | Evaluate an analysis against a profile |
| `GET /api/live/status`, `GET /api/live/interfaces` | admin | Live capture availability and interfaces |
| `POST /api/live/sessions`, `GET /api/live/sessions/{id}`, `POST /api/live/sessions/{id}/stop` | admin | Start, monitor and stop a live capture |
| `GET /health` | public | Service and TShark status, including the field check |

Request and response shapes and error codes are documented in [docs/api.md](docs/api.md).

## Dataset package

```bat
cd backend
..\.venv\Scripts\python -m app.dataset_export --zip
```

This writes `data/release/ipsec-sih26160-dataset-<date>/`, containing:
- the labelled strongSwan captures and lab sessions (pcap and JSON ground truth);
- feature tables with the exact group split and cross-validation fold each row had in training;
- a feature dictionary, a dataset card, `manifest.json` and `SHA256SUMS`.

ISCX raw captures are never included, only derived features and the citation. `--no-pcaps` leaves out the pcap files and `--verify <dir>` checks a package. See [docs/dataset.md](docs/dataset.md).

## Security controls

- **Authentication and authorization.** JWT (HS256) signed with `JWT_SECRET`, and scrypt password hashes. Passwords need 12+ characters from three character classes. Accounts lock after 5 failed logins in 15 minutes.
- **Isolation.** Analysts only see their own captures; viewers have read-only access to everything. An analysis you can't access returns 404, so IDs can't be probed.
- **Upload safety.** Extension allow-list, pcap/pcapng signature check, size limit, and sanitized filenames with no path components or hidden files. Files are stored content-addressed outside the database.
- **TShark safety.** It runs as an argument list with no shell, a timeout on every pass, and stderr captured and bounded. Live capture (dumpcap) is limited to configured roles, exact interface names and preset filters. The Docker image disables setuid dumpcap and runs as a non-root user.
- **Leak prevention.** Generic 500 responses, security headers, `Cache-Control: no-store` on the API, and PDFs marked confidential.
- **Audit log.** Logins (success, failure, lockout), uploads (including rejected ones), views, report generation and downloads, deletions, user changes and live captures.
- **Secrets.** Kept only in environment variables and `.env` files, which are gitignored. The testbed generates a fresh pre-shared key on every run.

## Project layout

```
backend/app/
  api/          auth, captures, analyses and dashboard, reports and audit, compliance, live, health
  core/         models, schemas, security (hashing, JWT, throttle), deps (RBAC), audit
  packet/       tshark wrapper, field_map, iana tables, ike, esp, esp_structure, rekey, traffic, features
  security/     rules, scoring, findings
  compliance/   engine + profiles/ (NIST SP 800-77r1, CNSA RFC 9206, org baseline)
  ml/           features, preprocessing, train, predict, iscx importer, protocol_models (mode + cipher)
  reports/      narrative (facts + template), llm (grounded), pdf, executive, technical, service
  db/           database (Alembic), repositories
  pipeline.py   parse -> inference -> ML -> rules -> compliance -> confidence
  confidence.py AI confidence score;   live.py  dumpcap live capture;   worker.py  background queue
  evaluation.py ground-truth evaluation;   dataset_export.py  dataset package
backend/migrations/   Alembic revisions
backend/tests/        unit, API, parser integration (generated pcaps), testbed ground truth
frontend/             Next.js dashboard: login, dashboard, upload, analyses, detail tabs, live capture, admin
testbed/              strongSwan Docker testbed, scenarios, traffic generator, runner, WSL netns recorder
docs/                 architecture, methodology, user guide, API, model card, evaluation, dataset card, deployment
data/                 supplied synthetic CSV; raw/ captures; processed/ features and evaluation; models/; release/
```

## Limitations

- **No decryption.** Nothing encrypted is decrypted. The IKEv2 authentication method and exact child SA transforms stay unavailable. PFS and lifetimes are inferred only when the capture contains a rekey. Mode and cipher family are predictions, and AES key length cannot be told from packet sizes.
- **Traffic categories are probabilistic** inferences from metadata, and the testbed traffic generators approximate real applications.
- **Testbed coverage.** Only PSK authentication is covered, and NAT-T is forced rather than caused by a real NAT.
- **In-process worker.** The analysis worker runs inside the API process. The `AnalysisQueue` boundary is where a distributed queue would plug in.
