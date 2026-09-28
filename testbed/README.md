# strongSwan capture testbed

Generates real IKE/ESP captures with known configurations, so the analyzer can be checked against ground truth instead of the synthetic CSV.

Two strongSwan 5.9 peers run in Docker on one bridge network:

| Peer | Role | Outer address | Protected ("inner") network |
|---|---|---|---|
| `moon` | initiator, captures traffic | 172.30.0.10 / fd00:30::10 | 10.1.0.0/24, fd00:1::/64 |
| `sun` | responder, runs traffic servers | 172.30.0.20 / fd00:30::20 | 10.2.0.0/24, fd00:2::/64 |

IPsec runs in the Linux kernel (XFRM) of Docker Desktop's WSL2 VM, or of the host on Linux.

## Run

From the repository root, with Docker running:

```powershell
.\.venv\Scripts\python.exe testbed\scripts\run_testbed.py                      # all scenarios
.\.venv\Scripts\python.exe testbed\scripts\run_testbed.py --only capture_005    # one scenario
```

Output goes to `data/raw/testbed/` (gitignored):

- `capture_NNN.pcap`: what tcpdump on `moon` saw on the wire. The filter keeps only IKE (UDP 500/4500), ESP and AH, which also drops the decrypted copies of inbound packets that Linux re-injects on the interface.
- `capture_NNN.json`: ground truth. The flat fields follow the project's ground-truth format. `ike_sa` and `child_sa` are authoritative, and `negotiated_sas` is strongSwan's own `swanctl --list-sas` output for audit.
- `manifest.csv`: one row per capture.

Then check the parser against them:

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest tests\test_testbed_captures.py -v
```

## ML training sessions (`--dataset`)

```powershell
.\.venv\Scripts\python.exe testbed\scripts\run_testbed.py --dataset --repeats 2
```

For each scenario this brings the SA up once, then records one pcap per traffic session: every traffic class × `--repeats`, with varying durations (8–20 s) and seeds. Output goes to `data/raw/traffic_sessions/` as `<scenario>_<class>_<nn>.pcap` plus a `.json` label, where `group` is the scenario ID. The trainer (`python -m app.ml.train --source sessions`) splits by that group, so held-out test scores come from configurations the model never saw. A failed session is retried once, then skipped.

## ML sessions without Docker (`netns_sessions.py`)

When Docker Desktop is unavailable or unstable, record the same traffic classes in any Linux, including WSL Ubuntu, using network namespaces:

```bash
sudo apt install -y iproute2 tcpdump iputils-ping
sudo python3 testbed/scripts/netns_sessions.py --repeats 3
```

The two namespaces are joined by a veth pair (MTU 1500). The kernel encrypts the traffic with manually keyed ESP SAs, and the 17 profiles cover AES-GCM, AES-CBC with SHA-256 or SHA-1, 3DES and ESP-NULL, tunnel and transport mode, NAT-T and IPv6. `--profiles <name> ...` re-records only the named profiles (existing sessions with the same name are overwritten). Every captured packet is real kernel-generated ESP. The captures contain no IKE, because the traffic classifier only uses the ESP data plane. Sessions are labelled `dataset_origin: linux_xfrm_netns_capture` with `group` set to the profile name.

## Real phone apps through a real VPN (`record_real_app.py`)

For real application traffic such as WhatsApp, a strongSwan road-warrior server (`docker-compose.phone.yml`) accepts a phone's built-in IKEv2/IPsec PSK client on UDP 500/4500 and NATs its traffic to the internet. Each recording is saved to `data/raw/traffic_sessions/` as `<app>_<activity>_<nn>.pcap` plus a `.json` label, with `dataset_origin: real_app_phone_ikev2` and the IKE/ESP settings the phone actually negotiated.

```bat
python testbed\scripts\record_real_app.py serve --build     :: first time; prints the phone settings
python testbed\scripts\record_real_app.py status
python testbed\scripts\record_real_app.py record --activity voice-call --seconds 120
python testbed\scripts\record_real_app.py stop
```

Full procedure, including the live dashboard demo and troubleshooting: [docs/whatsapp-live.md](../docs/whatsapp-live.md).

## Per-scenario steps

1. Write `swanctl` configs for both peers into `testbed/generated/` (gitignored), with a fresh random pre-shared key.
2. Restart both peers so no SA state carries over.
3. Start tcpdump on `moon`, then initiate the IKE SA and child SA.
4. Run the scenario's traffic generator (`scripts/traffic.py`) between the protected networks (tunnel mode) or the peers themselves (transport mode).
5. Tear the SA down, which captures the delete exchange, then stop tcpdump and write the ground truth.

## Scenarios

Defined in `configs/scenarios.json`:

| ID | Scenario | Traffic |
|---|---|---|
| 001 | IKEv2 tunnel, AES-256-GCM, DH14, PFS | Video |
| 002 | IKEv2 tunnel, AES-128-GCM, DH19 (ECP-256), PFS | VoIP |
| 003 | IKEv2 transport, AES-256-CBC + SHA-256, no PFS | Web |
| 004 | IKEv2 tunnel, AES-128-CBC + SHA-256, PFS | File-Transfer |
| 005 | IKEv1 Main Mode tunnel, AES-128 + SHA-1, MODP-1024 (legacy) | ICMP |
| 006 | IKEv2 tunnel, AES-256-GCM, PFS disabled | Chat |
| 007 | IKEv2 tunnel over IPv6, ECP-384 | Email |
| 008 | IKEv2 tunnel with NAT-T (UDP 4500 forced with `encap = yes`) | Web |
| 009 | IKEv2 tunnel, ESP-NULL (mode visible on the wire) | ICMP |
| 010 | IKEv2 transport, ESP-NULL (mode visible on the wire) | ICMP |
| 011 | IKEv2 tunnel, **AH** (HMAC-SHA256, no encryption) | ICMP |
| 012 | IKEv2 transport, **AH** | Web |
| 013 | IKEv2 tunnel **plus unprotected normal traffic** (full capture, no filter) | VoIP + plain Web |
| 014 | **Normal traffic only, no IPsec** (baseline) | Web |
| 015 | IKEv2 with **rekeys** every 20 s (child) / 45 s (IKE), **PFS** MODP-2048 | VoIP, 70 s |
| 016 | IKEv2 with rekeys, **no PFS** | VoIP, 70 s |
| 017 | IKEv2 with rekeys, **PFS** ECP-256 (smallest key exchange) | VoIP, 70 s |

To add a scenario, append an entry with strongSwan proposal strings and the expected `truth` values in the analyzer's naming (see `backend/app/packet/iana.py`).

## Limits

- Authentication is PSK only; certificate-based scenarios are not covered yet.
- NAT-T is forced rather than caused by a real NAT, so NAT detection hashes won't show a real address change.
- Traffic classes are shaped approximations (packet size, rate and direction), not recordings of real applications.
- Each capture holds one short session, with no rekeying.
