# Understanding part (b): traffic capture

This document explains part (b) of the problem statement in plain language: what traffic capture is, what each required kind of traffic means, and exactly what this project built for it. Part (a) (the testbed) is in [understanding_1.md](understanding_1.md).

> **The requirement.** Acquire network traces using tools such as Wireshark, tcpdump and custom packet capture utilities. The captured dataset should include IKE negotiation, ESP packets, AH packets (optional) and normal communication.

---

## 0. The basics

### What is a "network trace" or "capture"?

A **capture** is a recording of network packets, like a CCTV recording of a road that shows every vehicle that passed, when, and how big it was. It is saved as a **`.pcap`** or **`.pcapng`** file.

Our analyzer works **only from captures**. It never logs in to a VPN device and never decrypts anything. So the quality of the captures decides what can be analysed:
- A capture **without the IKE negotiation** can't show which cipher was chosen.
- A capture **without ESP traffic** can't show what the tunnel carries.

That is why part (b) lists what a good dataset must contain.

### The capture tools

| Tool | What it is |
|---|---|
| **tcpdump** | Command-line packet recorder on Linux. Small, scriptable; the standard tool on servers and gateways |
| **Wireshark** | Graphical packet analyser. Its engines are **dumpcap** (records packets) and **TShark** (decodes packets on the command line) |
| **Custom capture utility** | A purpose-built program that captures, and here also analyses and labels, traffic automatically |

---

## 1. Capture tools: what we built

### tcpdump, inside both testbeds

| Where | What it records |
|---|---|
| `testbed/scripts/run_testbed.py` (strongSwan Docker testbed) | Runs tcpdump on the VPN gateway *moon* for each of the 17 scenarios, into `capture_NNN.pcap` |
| `testbed/scripts/netns_sessions.py` (Linux namespace testbed, run in WSL) | Runs tcpdump inside the Linux namespace for each of the 357 training sessions |

**Capture filter** (records only VPN traffic):

```
udp port 500 or udp port 4500 or ip proto 50 or ip proto 51      (plus the ip6 equivalents)
   ▲ IKE         ▲ IKE / NAT-T      ▲ ESP           ▲ AH
```

Scenarios that must include **normal communication** (capture_013 and capture_014) record with **no filter**, so everything on the wire is kept.

### Wireshark's engines, inside the analyzer

| Engine | Where | Job |
|---|---|---|
| **TShark** | `backend/app/packet/tshark.py` | Decodes every capture in two passes: (1) one row per packet with sizes, times, addresses and ESP/AH numbers; (2) full detail of every IKE message. Every field name is checked against the installed Wireshark at start-up |
| **dumpcap** | `backend/app/live.py` | Records live traffic for the Live capture feature |

### Custom capture utilities (our own)

**1. Live capture, in the dashboard** (`backend/app/live.py`, `backend/app/api/live.py`, `frontend/app/(app)/live/`)

```
 Admin picks:  interface (Wi-Fi / Ethernet)  +  filter (IPsec only / All traffic)  +  duration
                                 │
                                 ▼
             dumpcap records to a file ──► every 5 s: quick re-analysis while still recording
                                 │             (packets, IPsec detected?, IKE version, ESP rate, SPIs, score)
                                 ▼
             on finish or Stop: stored like an upload ──► full analysis ──► link to the result
```

What makes it more than plain Wireshark:
- **Analysis while recording.** You see "IPsec detected, IKEv2, 2 SPIs, score 95" before the capture even ends.
- **Safety built in:**
  - the interface must be one the system actually lists, and filters are presets only, so nobody can inject commands;
  - maximum 5 minutes and 100 MB by default;
  - one capture at a time;
  - admin only by default;
  - every start and stop is written to the audit log.
- **A clean stop on Windows.** dumpcap is told to finish properly, so the file is never corrupted.

**2. Testbed recorders** (`run_testbed.py`, `netns_sessions.py`)

These don't just record, they produce **labelled** data:

```
 configure VPN ──► start tcpdump ──► bring VPN up (IKE) ──► generate traffic ──► stop tcpdump
                                                                                   │
                                     capture_006.pcap  (the packets)  ◄────────────┤
                                     capture_006.json  (the answer key: true cipher, DH, PFS, mode, traffic)
```

A plain recording tells you what happened. A recording **plus its answer key** lets you *prove* the analyzer is right, and lets the AI *learn*.

---

## 2. The four kinds of traffic the dataset must contain

### IKE negotiation

**What it is.** The "handshake" before the VPN starts. The two sides propose and agree on ciphers, integrity algorithm and DH group, then prove their identities. In IKEv2 the first exchange (**IKE_SA_INIT**) is in **cleartext**, which is why the chosen cryptography can be read directly. Later exchanges (IKE_AUTH, and CREATE_CHILD_SA for rekeys) are encrypted.

```
 moon ──IKE_SA_INIT request  (offers: AES-256-GCM, SHA-256, DH14)──►  sun      ← cleartext
 moon ◄─IKE_SA_INIT response (selects: AES-256-GCM, DH14)──────────  sun      ← cleartext
 moon ──IKE_AUTH ─────────── (identities, tunnel settings)────────►  sun      ← encrypted
 moon ◄─IKE_AUTH ──────────────────────────────────────────────────  sun      ← encrypted
      ... later: CREATE_CHILD_SA (rekey) ...                                    ← encrypted, but its SIZE reveals PFS
```

**Why the dataset needs it.** Without it, the cipher, DH group and IKE version can't be observed; they would all show "not observable".

**What our dataset contains.**

| Kind | Captures |
|---|---|
| IKEv2 IKE_SA_INIT + IKE_AUTH | capture_001–013, 015–017 |
| **IKEv1** Main Mode + Quick Mode (legacy) | capture_005 |
| **Rekeys** (CREATE_CHILD_SA), for PFS and lifetime inference | capture_015, 016, 017 (e.g. 28 IKE messages in capture_017) |
| IKE moved to UDP 4500 (NAT-T and MOBIKE) | capture_008, and all IKEv2 captures after the first exchange |

**Result.** IKE version, encryption, integrity, PRF and DH group are **100% correct** on all 16 IPsec captures.

### ESP packets

**What they are.** The actual VPN data: the protected user traffic, **encrypted**. Visible on the wire: the outer IP header, the **SPI** (which SA the packet belongs to), a **sequence number**, and the packet's **size and timing**. Everything else is scrambled.

```
 [ outer IP header ][ SPI | sequence no. ][ ███ encrypted data ███ ][ integrity tag ]
    visible            visible                hidden                  visible (meaningless)
```

**Why the dataset needs it.** It is 99% of VPN traffic. Its sizes and timing are all that is left to infer the **mode**, the **cipher family** and the **type of traffic**, which is the AI part of the project.

**What our dataset contains.**

| Source | Amount |
|---|---|
| strongSwan captures (001–010, 013, 015–017) | 14 captures, e.g. 7,000 ESP packets in capture_017 |
| Lab training sessions (Linux kernel ESP, 17 cipher/mode profiles) | 357 sessions |
| strongSwan training sessions | 17 sessions |
| Real applications (ISCX 2016, converted to ESP sizes) | 1,116 windows from 30 captures |
| Special cases | NAT-T (ESP inside UDP 4500, capture_008), IPv6 (capture_007), **ESP-NULL**, i.e. no encryption (009, 010) |

**Result.** SPIs and NAT-T 100% correct; mode AI 97%; cipher AI 100% when decided; traffic type 83.2% on real apps and 100% on the testbed.

### AH packets (optional)

**What they are.** **AH (Authentication Header)** protects **integrity only**: it proves the packet wasn't changed, but the data travels **readable**. It is rarely used today, and using it for confidential data is a serious mistake.

```
 [ IP header ][ AH: SPI | seq | integrity tag ][ data — READABLE by anyone ]
```

**What our dataset contains.**
- capture_011: AH in **tunnel** mode
- capture_012: AH in **transport** mode

**Result.**
- Detected as AH ✔
- Mode read directly (because AH isn't encrypted) ✔
- NAT-T correctly "No", because AH can't pass through NAT ✔
- Flagged **Critical: "Payload not encrypted"** (rule CRYPTO-005) ✔

### Normal communication

**What it is.** Ordinary traffic that is **not** inside a VPN: web, ping and so on, travelling in the clear.

**Why the dataset needs it.** Real networks carry both. The analyzer must:
1. **find** the IPsec traffic among everything else, and analyse only that;
2. **not** raise false alarms when there is no VPN at all.

**What our dataset contains.**

| Capture | Content | Expected result | Our result |
|---|---|---|---|
| capture_013 | VPN (VoIP inside ESP) **mixed with** normal unprotected web traffic | IPsec found; features computed on the IPsec flow only | ✔ IPsec detected, VoIP predicted correctly, tunnel mode predicted |
| capture_014 | **Only** normal traffic, no VPN | "IPsec not detected", no IPsec findings | ✔ Correct; no false findings |

The ISCX dataset also contains **non-VPN** captures of the same apps, which can be imported with `python -m app.ml.iscx --include-nonvpn`.

---

## 3. Where everything is stored

```
data/raw/testbed/              17 labelled strongSwan captures: capture_NNN.pcap + capture_NNN.json (answer key) + manifest.csv
data/raw/traffic_sessions/     374 labelled ESP sessions (pcap + json label) for AI training
data/raw/iscx2016/             ISCX VPN-nonVPN 2016 public captures (downloaded; not redistributed)
storage/pcaps/                 every capture uploaded or recorded live through the app
data/release/<package>/        the exported dataset package (python -m app.dataset_export --zip)
```

A captured-dataset **manifest** lists each testbed capture with its true settings: `data/raw/testbed/manifest.csv`.

---

## 4. Summary table

| Requirement | Built | Where | Verified |
|---|---|---|---|
| tcpdump | ✅ in both testbeds | `testbed/scripts/run_testbed.py`, `netns_sessions.py` | 17 + 357 captures recorded |
| Wireshark | ✅ TShark (decoding), dumpcap (live) | `backend/app/packet/tshark.py`, `backend/app/live.py` | Field check at start-up (`/health`) |
| Custom capture utility | ✅ Live capture with rolling analysis; labelled testbed recorders | Live capture page; `testbed/scripts/` | Tested on Wi-Fi, including early stop |
| IKE negotiation | ✅ IKEv1, IKEv2, rekeys | capture_001–013, 015–017 | 100% on cryptography |
| ESP packets | ✅ incl. NAT-T, IPv6, ESP-NULL | 14 captures + 374 sessions + 1,116 real-app windows | See ESP results above |
| AH packets (optional) | ✅ tunnel and transport | capture_011, capture_012 | Detected; flagged Critical |
| Normal communication | ✅ mixed and pure | capture_013, capture_014 | No false alarms |

**One line for the judges:**

> *"We capture with tcpdump in our testbeds and with Wireshark's dumpcap in our own live-capture tool, which analyses traffic while it's still recording. Every testbed capture comes with an answer key, and the dataset covers IKEv1 and IKEv2 negotiation with rekeys, ESP (including NAT-T, IPv6 and unencrypted ESP-NULL), AH in both modes, and normal traffic with and without a VPN."*
