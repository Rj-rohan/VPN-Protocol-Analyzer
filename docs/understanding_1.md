# Understanding part (a): the VPN testbed

This document explains, in plain language, every item in part (a) of the problem statement: what it means, why it matters for security, what this project built for it, and how the analyzer detects it. The longest section covers **tunnel mode vs transport mode**, because that is the item people most often find confusing.

> **The requirement.** Develop a laboratory environment capable of establishing IPsec VPNs using multiple configurations: tunnel mode, transport mode, AES-128, AES-256, AES-GCM, AES-CBC + HMAC, different DH groups, PFS enabled or disabled, IPv4 and IPv6, and different types of traffic (VoIP, WhatsApp, e-mail, web browsing, ICMP, video streaming, etc.).

---

## 0. First, the basics

### What is a VPN?

A **VPN** (Virtual Private Network) builds a protected "pipe" across an untrusted network such as the internet. Anyone watching the wire sees only scrambled data going between the two ends of the pipe.

### What is IPsec?

**IPsec** is the most common VPN technology in companies, governments and clouds. It has two parts:

| Part | Job | Analogy |
|---|---|---|
| **IKE** (Internet Key Exchange), versions 1 and 2 | The two ends **agree** on the security settings (which cipher, which key size) and create shared secret keys | Two people agreeing on a lock and exchanging keys before sending letters |
| **ESP** (Encapsulating Security Payload) | Carries the actual data, **encrypted** and integrity-protected | The locked letters themselves |
| **AH** (Authentication Header, optional) | Protects integrity only: proves the data wasn't changed, but does **not** hide it | A tamper-evident seal on an open postcard |

The agreed settings are called a **Security Association (SA)**. Each SA has an ID number, the **SPI**, which is visible in every packet.

### Why a testbed is needed

To prove the analyzer is right, you need captures where **the true answer is known**. A testbed is a lab where *we* set up VPNs with chosen settings, record their traffic, and save the settings as an answer key. Then we check that the analyzer, looking only at the recorded packets, gets the answer right.

**What we built: two testbeds**

| Testbed | What it is | Used for |
|---|---|---|
| **strongSwan Docker testbed** (`testbed/scripts/run_testbed.py`) | Two real VPN gateways (strongSwan 5.9.8, the software many companies use) in Docker containers named *moon* and *sun*. They negotiate the VPN with IKE exactly like a real deployment. **17 scenarios.** | Testing the whole analyzer against an answer key (`capture_NNN.json`) |
| **Linux namespace recorder** (`testbed/scripts/netns_sessions.py`, run in WSL) | Two virtual machines-in-a-box inside Linux, with the Linux kernel encrypting traffic between them. **17 encryption profiles × 7 traffic types × 3 repeats = 357 sessions.** | Training the AI models |

---

## 1. Tunnel mode vs transport mode

### What they are

Every IP packet has a **header** (like an envelope: *from* address, *to* address) and a **payload** (the letter inside). IPsec can protect a packet in two ways.

**Transport mode** encrypts only the payload. The original header stays in front, readable:

```
Original packet:   [ IP header: PC-A → PC-B ][ TCP + data ]

Transport mode:    [ IP header: PC-A → PC-B ][ ESP ][ TCP + data (encrypted) ][ ESP trailer ]
                     ▲ still readable: everyone sees that PC-A talks to PC-B
```

**Tunnel mode** encrypts the **whole original packet, header included**, and puts a new outer header in front that names only the two VPN gateways:

```
Original packet:   [ IP header: PC-A → PC-B ][ TCP + data ]

Tunnel mode:       [ New IP header: Gateway-1 → Gateway-2 ][ ESP ][ IP header: PC-A → PC-B + TCP + data (all encrypted) ][ ESP trailer ]
                     ▲ only the gateways are visible          ▲ the real computers are hidden inside
```

### An everyday analogy

- **Transport mode:** you seal the letter inside the envelope, but the envelope still shows the real sender's and receiver's home addresses.
- **Tunnel mode:** you put the whole envelope inside a second envelope addressed from *your office's mailroom* to *their office's mailroom*. Outsiders see only the two mailrooms; they can't tell which employees are writing to each other.

### Where each is used

| Mode | Typical use | Example |
|---|---|---|
| **Tunnel** | **Site-to-site** VPNs between two gateways, and remote-access VPNs (laptop to office) | Head office network ↔ branch office network; your laptop ↔ company VPN |
| **Transport** | **Host-to-host** protection between two specific servers that talk directly | Database server ↔ application server in the same data centre; L2TP/IPsec |

### Why detecting the mode matters for security

1. **Metadata exposure.** In transport mode, the real IP addresses of both computers are visible to anyone on the path. An attacker learns *which* machines talk, *when*, and *how much*, which is useful for mapping a network and picking targets. Tunnel mode hides the internal addresses. The analyzer raises rule **META-001, "Endpoint addresses exposed (transport mode)"**, when it finds transport mode.
2. **Policy compliance.** Many organisations require tunnel mode for traffic between sites. The *org-baseline* compliance profile has control **ORG-05, "Tunnel mode"**.
3. **Detecting misconfiguration.** If a site-to-site VPN turns out to use transport mode, someone configured it wrongly.
4. **Understanding the deployment.** The mode tells an auditor what kind of VPN this is (gateway-to-gateway or host-to-host) without logging in to any device.

### Why it is hard to detect

The mode is decided inside the **encrypted** part of the IKE negotiation, and in ESP the only thing that differs between the modes is **inside the encrypted payload** (whether an inner IP header is there). Looking at an encrypted ESP packet, you can't directly see which mode it uses. Ordinary tools such as Wireshark just show "ESP, encrypted". This is exactly why the problem statement asks for **AI** to *infer* the mode.

### How our analyzer detects it: three levels

| Level | When it applies | How | Label shown |
|---|---|---|---|
| **1. Read it directly** | The traffic is **AH**, or **ESP-NULL** (not encrypted) | The inner packet is readable, so we can see whether an inner IP header is there | `observed` (certain) |
| **2. Physical rule** | Encrypted ESP | We work out the cipher's overhead (from the packet-size pattern), subtract it, and get the size of the inner packet. **An inner packet smaller than 28 bytes cannot contain an IP header (20 bytes) plus a transport header (8 or more bytes)**, so it *must* be transport mode | `predicted`, 99% |
| **3. AI model (RandomForest)** | Encrypted ESP, no tiny packets | Tunnel mode adds **20 extra bytes (IPv4) or 40 (IPv6) to every packet**. This shows most clearly in TCP acknowledgements, the smallest common packet: in transport mode they are about 20–32 bytes inside, in tunnel mode about 40–52. The model learned these size patterns from 370 labelled sessions | `predicted`, with confidence |

**Accuracy:** 92.9% ± 2.6% in cross-validation (VPN configurations it never saw during training, averaged over 5 splits), 13 of 14 correct on the separate strongSwan test captures, and 98.4% on real WhatsApp and Gmail phone traffic.

**Real example from our testbed:**
- **capture_003** (transport mode, AES-CBC): the smallest inner packet works out to about **22.5 bytes**, too small to hold an IP header, so the result is **Transport, 99%**. ✔ Correct.
- **capture_008** (tunnel mode, AES-GCM): the smallest inner packet is about **52.5 bytes**, a TCP acknowledgement plus a 20-byte inner IPv4 header, so the result is **Tunnel, 99%**. ✔ Correct.

### What we implemented for it

| Item | Where |
|---|---|
| Tunnel-mode scenarios | 13 of 17 strongSwan scenarios (e.g. 001, 002, 004–009, 011, 013, 015–017) |
| Transport-mode scenarios | capture_003 (AES-CBC), capture_010 (ESP-NULL), capture_012 (AH) |
| Lab training profiles | 17 profiles, both modes: e.g. `ns-gcm256-tunnel-v4` and `ns-gcm256-transport-v4` |
| Detection | `backend/app/packet/esp.py` (observed), `backend/app/packet/esp_structure.py` (inner sizes), `backend/app/ml/protocol_models.py` (rule + AI) |
| Security rule | META-001 in `backend/app/security/rules.py` |

---

## 2. AES-128 and AES-256

**What it means.** **AES** (Advanced Encryption Standard) is the cipher that scrambles the data; it is the world standard. The number is the **key length in bits**:

| | AES-128 | AES-256 |
|---|---|---|
| Key length | 128 bits | 256 bits |
| Strength | Strong today | Stronger, with a larger safety margin (also against future quantum computers) |
| Who requires it | Most commercial policies accept it | **Top-secret / CNSA** (RFC 9206) requires AES-256 |

**Why it matters.** A compliance check (for example CNSA's "AES-256 encryption") fails if AES-128 is used where AES-256 is required.

**What we implemented.**
- **AES-128:** capture_002 (AES-128-GCM), capture_004 (AES-128-CBC), capture_005 (AES-128-CBC, IKEv1), capture_017 (AES-128-GCM); lab profiles `gcm128` and `cbc128`.
- **AES-256:** capture_001, 003, 006–013, 015, 016; lab profiles `gcm256` and `cbc256`.

**How we detect it.** The IKE negotiation (IKE_SA_INIT) is **not encrypted**, so the chosen cipher and key length are read directly from it, for example "AES-256-GCM-16, observed". Accuracy is 100% on all 16 IPsec test captures.

*Honest limit:* inside encrypted ESP, AES-128 and AES-256 produce **identical packet sizes**, so the key length of the data channel can't be inferred from packets. The analyzer says so explicitly instead of guessing.

---

## 3. AES-GCM vs AES-CBC + HMAC

AES can run in different **modes of operation**. The two in the requirement are:

| | **AES-GCM** | **AES-CBC + HMAC** |
|---|---|---|
| Type | **AEAD**: encryption and integrity in one step | Two separate steps: CBC encrypts, then HMAC (e.g. HMAC-SHA-256) checks integrity |
| Speed | Faster, and hardware-accelerated | Slower (two passes) |
| Safety | Modern and preferred; fewer ways to misconfigure | Fine if configured correctly; older design, with past attacks on CBC padding |
| Packet layout | 8-byte IV, 4-byte padding blocks, 16-byte tag | 16-byte IV, 16-byte padding blocks, 12- or 16-byte tag |

**Why it matters.** NIST and most modern policies prefer AEAD (GCM). Using CBC with **SHA-1** or **MD5** is outdated (rule **CRYPTO-002**). The *org-baseline* profile requires AES-GCM (controls ORG-02 and ORG-07).

**What we implemented.**
- **AES-GCM:** most scenarios (001, 002, 006–008, 013, 015–017); lab profiles `gcm128` and `gcm256`.
- **AES-CBC + HMAC-SHA-256:** capture_003, capture_004; lab profiles `cbc128-sha256` and `cbc256-sha256`.
- **AES-CBC + HMAC-SHA-1:** capture_005 (legacy); lab profiles `cbc128-sha1`.
- **Weak ciphers, as negative examples:** 3DES (`ns-3des-*`), and ESP-NULL, meaning no encryption at all (capture_009, capture_010, `ns-null-*`).

**How we detect it.**
- **From IKE (observed):** read directly from the negotiation, 100%.
- **From encrypted ESP (AI, no training needed):** each cipher pads packets differently, so the *set* of packet sizes gives it away. GCM packets fall on a 4-byte grid, while CBC packets all fall on a 16-byte grid. If 10 different packet sizes all sit on a 16-byte grid, the chance of that happening with GCM is (1/4)¹⁰, about 1 in a million. The analyzer calculates this probability (Bayesian inference). It was **100% correct on all 291 samples** where it reached a decision. If there are too few distinct sizes (for example a VoIP call where every packet is the same size), it says "undecided" instead of guessing.

---

## 4. Different DH groups

**What it means.** **Diffie-Hellman (DH)** is the maths trick that lets two sides agree on a secret key over a public network without ever sending the key. The **DH group** is the size or type of the maths used. Bigger or elliptic-curve groups are stronger:

| Group | Name | Strength | Status |
|---|---|---|---|
| 1, 2, 5 | MODP-768 / 1024 / 1536 | Weak | **Broken or deprecated.** 1024-bit groups are within reach of well-funded attackers |
| 14 | MODP-2048 | Adequate | Minimum acceptable (NIST) |
| 15, 16 | MODP-3072 / 4096 | Strong | Recommended |
| 19, 20, 21 | ECP-256 / 384 / 521 (elliptic curves) | Strong and fast | Recommended; ECP-384 is required by CNSA |

**Why it matters.** A weak DH group lets an attacker who records the traffic compute the keys later and decrypt everything. Rule **CRYPTO-001** flags weak groups, and control **NIST-05** checks for a strong group.

**What we implemented.** Four different groups across the strongSwan scenarios:

| Group | Scenario |
|---|---|
| DH2 (MODP-1024, **weak**) | capture_005 (IKEv1 legacy): CRYPTO-001 fires ✔ |
| DH14 (MODP-2048) | capture_001, 003, 004, 006, 008–013, 015, 016 |
| DH19 (ECP-256) | capture_002, capture_017 |
| DH20 (ECP-384) | capture_007 |

**How we detect it.** Read directly from the IKE negotiation (observed). **100%** on every test capture.

---

## 5. Perfect Forward Secrecy (PFS) enabled or disabled

**What it means.** A VPN changes its keys regularly; this is called **rekeying**. With **PFS**, every new key comes from a **fresh** Diffie-Hellman exchange, so the keys are independent of each other. Without PFS, new keys are derived from the old secret.

**Why it matters.** Suppose an attacker records months of encrypted traffic and later steals one key (say, by hacking the VPN server):
- **Without PFS:** that one key can unlock **all** the recorded traffic, past and future.
- **With PFS:** it unlocks only one short period. Everything else stays safe.

That is why NIST requires PFS (control **NIST-06**) and rule **CRYPTO-003, "PFS disabled"** is High severity.

**What we implemented.**
- **PFS on:** capture_001, 002, 004, 007, 008, 015 (MODP-2048), 017 (ECP-256)
- **PFS off:** capture_006, 016, and others without a DH group in the child proposal
- **Rekeying scenarios** (the VPN renews its keys every 20 seconds): capture_015 (PFS on), capture_016 (PFS off), capture_017 (PFS on with an elliptic curve)

**How we detect it: a clever inference.** In IKEv2, PFS is negotiated inside **encrypted** messages, so it normally can't be seen. But when the VPN rekeys, a PFS rekey message has to carry a new DH public key, which makes the (encrypted) message **bigger by a known amount**: 256 extra bytes for MODP-2048, 64 for ECP-256. The analyzer measures the size of each rekey message:
- rekey messages about 400 bytes with MODP-2048 → PFS **on**
- rekey messages about 150 bytes → PFS **off** (no key inside)

Result: **3 of 3** rekeying captures correct (on, off, and on with ECP-256), shown as *inferred* with the byte sizes as evidence. If a capture contains no rekey, PFS is honestly reported as *not observable*.

The same rekeys also reveal the **SA lifetime** (key lifetime), which IKEv2 never sends: capture_017 shows an IKE rekey every 45 s and a child rekey every 18 s (configured: 45 s and 20 s).

---

## 6. IPv4 and IPv6

**What it means.** The two versions of the Internet Protocol:
- **IPv4** addresses look like `192.168.1.10` (32 bits; the old standard, still most common).
- **IPv6** addresses look like `2001:db8::10` (128 bits; the modern standard, growing fast, and required in many government networks).

**Why it matters.** IPsec works over both, but the packet layouts differ (for example, the IPv6 header is 40 bytes instead of 20). An analyzer that only understands IPv4 would miss or misread IPv6 VPNs. Tunnel-mode detection also has to account for the 40-byte inner IPv6 header.

**What we implemented.**
- **IPv4:** all scenarios except 007.
- **IPv6:** capture_007 (IKEv2 over IPv6, AES-256-GCM, ECP-384); lab profiles `*-v6`, e.g. `ns-gcm256-tunnel-v6` and `ns-cbc256-sha256-transport-v6`.

**How we detect it.** Read from the outer IP header (observed). 100% correct.

---

## 7. Different types of traffic

**What it means.** The kind of activity *inside* the encrypted VPN: a phone call, a video, a file download and so on.

**Why it matters.** Even though the content is encrypted, **the sizes and timing of packets still reveal what kind of activity it is**. This is called *traffic analysis*. For a security assessment it matters for two reasons:
1. **Metadata leakage.** Proving that an observer can tell "this tunnel carries a phone call" without decrypting anything shows a real privacy exposure (rule **META-002**, with padding as the recommended fix).
2. **Operational insight.** An organisation can check whether its VPN carries what it should (for example, video streaming on a VPN meant for database replication is suspicious).

**The traffic types and their patterns:**

| Type | What its packets look like | Our label |
|---|---|---|
| **VoIP** (voice call) | Small packets (about 100–300 bytes), very regular, about 50 per second each way, both directions equal | VoIP |
| **WhatsApp** (chat and calls) | Chat: tiny sparse bursts. Calls: VoIP pattern | Chat / VoIP |
| **E-mail** | Short exchanges, then a burst when a message with attachments is sent | Email |
| **Web browsing** | A small request up, a burst of large packets down, then quiet while reading | Web |
| **ICMP** (ping) | Identical small request/reply pairs at a steady rate | ICMP |
| **Video streaming** | Large packets down in chunks every few seconds, little up | Video |
| **File transfer** (extra) | Continuous full-size packets in one direction | File-Transfer |

**What we implemented.**

| Source | Traffic | Amount |
|---|---|---|
| Lab (strongSwan + Linux namespace testbeds) | All 7 classes, generated by `testbed/scripts/traffic.py` | 374 sessions |
| **Real applications:** ISCX VPN-nonVPN 2016 public dataset (University of New Brunswick) | Real **Skype, Facebook and Hangouts chat and calls**, YouTube, Netflix, Vimeo, Spotify, email, SFTP and FTPS, used by real people | 1,116 windows from 30 captures |

**How we detect it.** A **RandomForest AI model** looks at 59 statistics of the encrypted packets (sizes, timing, direction, bursts, idle gaps) and predicts the class with a probability. Accuracy:
- **About 79–81% on real applications** (81.3% ± 2.1% over 5 splits), measured strictly: every capture is held out, so the model never saw any part of a test capture.
- **Real WhatsApp and Gmail** through a phone's VPN, never used for training: 5 of 9 recordings correct (chat, voice call, video call and 2 emails). Modern phone apps differ from the 2016 training apps, so more phone recordings are the next step.
- **100%** on the 16 strongSwan test captures.
- Weakest class: **Email (26%)**, because there are only 2 email captures to learn from.

**WhatsApp, honestly.** WhatsApp has **not yet been recorded** through our own IPsec VPN. The model already knows the same *kinds* of traffic from real messaging apps (Skype, Facebook Messenger and Hangouts chat and calls in the ISCX data), and WhatsApp chat and calls follow the same patterns. The planned next step is to connect a real phone or PC through a real IKEv2 VPN into the testbed and record WhatsApp chat and calls as additional labelled sessions.

---

## 8. Everything in one table

| Requirement | Meaning in one line | Implemented | Where | Detected by the analyzer |
|---|---|---|---|---|
| Tunnel mode | Whole packet encrypted, real addresses hidden | ✅ | 13 strongSwan scenarios + lab profiles | Observed (AH/ESP-NULL) or AI, about 93% |
| Transport mode | Only the payload encrypted, real addresses visible | ✅ | capture_003, 010, 012 + lab profiles | Observed or AI, about 93%; raises META-001 |
| AES-128 | 128-bit key | ✅ | capture_002, 004, 005, 017 | Observed, 100% |
| AES-256 | 256-bit key | ✅ | capture_001, 003, 006–013, 015, 016 | Observed, 100% |
| AES-GCM | Modern all-in-one encryption + integrity | ✅ | Most scenarios | Observed 100%; AI 100% when decided |
| AES-CBC + HMAC | Older two-step encryption + integrity | ✅ | capture_003, 004, 005 | Observed 100%; AI 100% when decided |
| Different DH groups | Key-agreement strength | ✅ DH2, 14, 19, 20 | capture_005, 001, 002, 007… | Observed, 100%; weak group raises CRYPTO-001 |
| PFS on/off | Fresh keys on each rekey | ✅ | capture_006, 015, 016, 017… | Inferred from rekey size, 3/3 |
| IPv4 / IPv6 | IP version | ✅ | capture_007 (IPv6), the rest IPv4 | Observed, 100% |
| VoIP, e-mail, web, ICMP, video | Traffic inside the tunnel | ✅ | Lab (374) + real apps (1,116) | AI: about 79–81% real apps, 100% testbed, 5/9 real phone apps |
| WhatsApp | Messaging-app traffic | ⚠️ Similar apps (Skype, Facebook, Hangouts) covered; WhatsApp itself pending | — | Would be classified as Chat or VoIP |
| *Extra:* AH, ESP-NULL, 3DES, NAT-T, IKEv1, rekeying, mixed and no-IPsec traffic | Weak and edge cases | ✅ | capture_005, 008–017 | All 100% on the testbed |

---

## Glossary

| Term | Meaning |
|---|---|
| **IKE** | The negotiation protocol that sets up the VPN (IKEv1 is old, IKEv2 is current) |
| **ESP** | The protocol that carries encrypted VPN data |
| **AH** | Integrity-only protection: data visible but tamper-proof |
| **SA / SPI** | Security Association (an agreed set of keys and settings) and its ID number |
| **AEAD** | Encryption and integrity in one algorithm (e.g. AES-GCM) |
| **HMAC** | A keyed checksum proving the data wasn't changed (e.g. HMAC-SHA-256) |
| **DH group** | The strength and type of the key-agreement maths |
| **PFS** | Fresh keys on every rekey, so one stolen key can't unlock everything |
| **Rekey** | Periodically replacing the keys |
| **NAT-T** | Wrapping ESP in UDP port 4500 so it can pass through home and office routers |
| **ESP-NULL** | ESP with no encryption (integrity only); flagged Critical |
| **Observed / inferred / predicted** | Read directly from packets / deduced by exact reasoning / estimated by AI with a confidence |
