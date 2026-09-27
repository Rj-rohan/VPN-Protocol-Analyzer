# IPsec encrypted-traffic dataset (SIH 26160)

Labelled IPsec captures and derived flow features for:

1. evaluating IPsec protocol analyzers against a known ground truth;
2. training traffic classifiers that work on encrypted ESP;
3. inferring tunnel/transport mode and ESP cipher family from packet lengths.

Released with the SIH 26160 *AI-Powered IPsec VPN Protocol Analyzer*. Build it with `python -m app.dataset_export` (see [Building the package](#building-the-package)).

## Contents

```
ipsec-sih26160-dataset-<version>/
├── README.md                     this card + package statistics
├── manifest.json                 counts, sources, split method, generator versions
├── SHA256SUMS                    checksum of every file (sha256sum -c format)
├── captures/
│   ├── testbed/                  capture_NNN.pcap + capture_NNN.json (full ground truth) + manifest.csv
│   └── sessions/                 <session>.pcap + <session>.json (traffic class, mode, proposal, group)
├── features/
│   ├── lab_sessions.csv          one row per lab session: labels, split, cv_fold, 59 traffic + 18 ESP features
│   ├── iscx_windows.csv          one row per 15 s ISCX window: labels, split, cv_fold, features (no raw data)
│   └── feature_dictionary.csv    every column with its role and description
├── splits/
│   └── groups.csv                group → source, rows, classes, split, cv_fold
└── results/                      evaluation report and model metrics at build time
```

`--no-pcaps` builds the same package without pcap files (labels, features and splits only).

## Sources

| `dataset_origin` | How it was produced | Ground truth |
|---|---|---|
| `strongswan_testbed_capture` | Two strongSwan 5.9.8 peers (Debian bookworm) in Docker, `testbed/scripts/run_testbed.py`; 17 scenarios covering IKEv1/IKEv2, tunnel/transport, IPv4/IPv6, NAT-T, PFS on/off, AES-GCM/CBC, ESP-NULL, AH, rekeying, and mixed or no IPsec | Configuration the runner rendered, plus `swanctl --list-sas` output |
| `linux_xfrm_netns_capture` | Linux kernel XFRM with manually keyed ESP between network namespaces (WSL Ubuntu), `testbed/scripts/netns_sessions.py`; 17 VPN profiles (GCM, CBC-SHA1/SHA256, 3DES, NULL; tunnel/transport; IPv4/IPv6; NAT-T) | The XFRM state the script installed |
| `iscx_vpn_2016_openvpn_converted` | ISCX VPN-nonVPN 2016 OpenVPN captures; each client packet converted to the size it would have as AES-GCM tunnel-mode ESP, real timing and direction kept, cut into 15 s windows (5 to 40 per capture) | Application class from the capture filename |

Traffic in the lab sources comes from the project's generators (`testbed/scripts/traffic.py`), which emulate each class: Web (request/response bursts), Video (paced chunks), VoIP (steady ~50 pps small packets), Email (SMTP-like exchanges), Chat (sparse short messages), ICMP (ping) and File-Transfer (bulk TCP).

## Labels

| Column | Values |
|---|---|
| `traffic_label` | Web, Video, VoIP, Email, Chat, ICMP, File-Transfer |
| `mode` | Tunnel, Transport (lab sources) |
| `esp_proposal` | strongSwan/XFRM proposal string, e.g. `aes128gcm16-ecp256` (lab sources) |
| `ip_version` | IPv4, IPv6 (lab sources) |
| `group` | Recording group: a VPN configuration (lab) or a source capture (ISCX) |

Testbed JSON files additionally hold the complete IKE SA and child SA parameters, the strongSwan proposals, PFS, NAT-T, authentication and the traffic generator settings.

## Splits

Windows of one recording resemble each other, so **all splits are by group**:

- **`split`**: 70/15/15 train/validation/test over groups, done separately inside each source (seed 26160). A source with fewer than 3 groups goes entirely to train.
- **`cv_fold`**: 5-fold `StratifiedGroupKFold` (shuffle, seed 26160) over all rows. The row is in the test fold `cv_fold`.

These are the exact assignments `app.ml.train` uses; the package is built by calling the same functions. Report **group-level** results. A random row split overstates accuracy (93.1% vs 83.2% on ISCX).

## Privacy and licensing

- **Lab captures** contain only generated traffic between private test addresses (10.x, 172.30.x, fd00::/8). The pre-shared keys are random per run and appear in no file.
- **ISCX raw captures are not redistributed.** The package holds only numerical features derived from them, plus the source filename for provenance. Anyone using `iscx_windows.csv` must cite:

  > G. Draper-Gil, A. H. Lashkari, M. S. I. Mamun, A. A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", *Proc. ICISSP 2016*, pp. 407–414. https://www.unb.ca/cic/datasets/vpn.html

- **Not included:** the synthetic CSV supplied with the problem statement, and trained model binaries.

## Known limitations

- Lab traffic is generated, not real users.
- ISCX ESP sizes are computed (AES-GCM tunnel framing), so ESP-structure features on those rows are not meaningful; mode and cipher labels exist only for lab rows.
- NAT-T in the testbed is forced (`encap=yes`), not caused by a real NAT.
- Only pre-shared-key authentication is exercised in the strongSwan scenarios.

## Building the package

```bat
cd backend
..\.venv\Scripts\python -m app.ml.iscx                               :: refresh ISCX features (needs the ISCX captures)
..\.venv\Scripts\python -m app.dataset_export --zip                  :: data\release\ipsec-sih26160-dataset-<date>\ (+ .zip)
..\.venv\Scripts\python -m app.dataset_export --source sessions      :: lab sessions only, no ISCX needed
..\.venv\Scripts\python -m app.dataset_export --verify data\release\ipsec-sih26160-dataset-<date>
```

Verify on Linux or macOS with `sha256sum -c SHA256SUMS`.
