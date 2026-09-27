# User guide

For the security engineers and analysts who use the dashboard. To install it, see [deployment.md](deployment.md).

## Signing in and roles

Open the dashboard (default http://localhost:3000) and sign in. The first administrator comes from `ADMIN_EMAIL` / `ADMIN_PASSWORD`; administrators create everyone else under **Users & audit**.

| Role | Sees | Can do |
|---|---|---|
| Viewer | All analyses | Read results, generate and download reports |
| Analyst | Own analyses | Upload captures, generate reports, delete own analyses |
| Admin | Everything | All of the above, plus live capture, users and the audit log |

Five wrong passwords in 15 minutes lock the account for 15 minutes.

## 1. Get a capture

Any `.pcap`, `.pcapng` or `.cap` up to 100 MB. Useful captures include:

- **The negotiation.** Start capturing *before* the tunnel comes up (or restart it), so the IKE_SA_INIT or Main Mode exchange is included. Without it, cryptographic parameters show as *not observable*.
- **Some traffic.** At least 10 ESP/AH packets for traffic classification (20 or more for the traffic-pattern rule); more varied traffic lets the ESP cipher inference decide.
- **Longer than the rekey interval** if you want lifetimes and PFS inferred.

Filters that keep captures small: `udp port 500 or udp port 4500 or esp or ah` (Wireshark or dumpcap) or `-f "ip proto 50 or ip proto 51 or udp port 500 or udp port 4500"` (tcpdump).

Sample captures with known answers are in `data/raw/testbed/` (`capture_NNN.pcap`, with ground truth in `capture_NNN.json`).

## 2. Upload

**Upload PCAP** → drop the file. The page shows upload progress, then the analysis steps. Analysis runs in the background (seconds for small files, up to about 2 minutes for 100 MB). The page moves to the analysis, which shows its progress and fills in when done.

## 3. Read the result

The header shows the IPsec verdict, IKE version, security score, risk level and predicted traffic class.

### Protocol details

The extracted configuration. **Every value has a badge that says where it came from:**

| Badge | Trust it as |
|---|---|
| observed | Read from a cleartext header; a fact |
| observed-majority | A fact, but messages disagreed; the evidence lists the other values |
| inferred | Deduced from structure (e.g. rekey sizes); reliable, with its reasoning shown |
| predicted | AI estimate with a confidence; confirm on the endpoint before acting |
| unavailable | Hidden by encryption; check the VPN configuration directly |

The Evidence column says which frames or measurements each value came from. The **AI protocol inference** panel shows the predicted mode and ESP cipher family with their probabilities. The selected proposal is shown separately from what the initiator offered.

### Security assessment

- **AI confidence score** (top). How much of this analysis rests on solid evidence, broken into components. A low score usually means the capture missed the negotiation.
- **Project Security Assessment Score** and risk level, with the formula.
- **Findings.** Each has its rule ID, condition, evidence and source.

### Compliance

Choose a profile (NIST SP 800-77r1, CNSA/RFC 9206, or your organisation's). Each control shows **Pass**, **Fail**, **Not observable** or **N/A**, with the evidence and a remediation. The verdict is *compliant*, *non-compliant* or *insufficient evidence*. The last means nothing failed, but some controls could not be checked from the capture.

### Threat matrix

Every finding with its severity, evidence, impact and recommendation, in one table for remediation planning.

### Traffic analysis

The predicted class and class probabilities, the model it came from and its measured accuracy, the packet-size histogram, and the traffic timeline (bytes up and down per second).

### Reports

- **Executive report.** One-page risk summary, compliance status and prioritised actions, for management.
- **Technical report.** Full configuration with sources, every finding, compliance controls, AI inference and the confidence breakdown, and methodology.

If an Anthropic API key is configured, the narrative is written by Claude from the analysis facts. Any sentence that names a value not in the facts is rejected, and the deterministic narrative is used instead. The report states which was used.

## Live capture (admin)

**Live capture** → choose an interface, a filter (*IPsec only* or *All traffic*) and a duration (up to 5 minutes and 100 MB by default) → **Start**.

- Every 5 seconds the page updates the packet count, IPsec detection, IKE version, ESP rate, SPIs and a provisional score.
- **Stop** ends early. The capture is then stored and analysed like an upload, and a link to the full result appears.

On Windows this needs Npcap (installed with Wireshark). Only one capture runs at a time, and every start and stop is written to the audit log.

## Dashboard

Totals, risk and severity distribution, traffic categories, the most frequent findings, the compliance overview for the default profile, and the average security score and AI confidence across your analyses.

## Users & audit (admin)

- **Users.** Create users, change roles, deactivate accounts or reset passwords.
- **Audit log.** Logins (including failures and lockouts), uploads (including rejected ones), views, report generation and downloads, deletions, live captures and user changes, each with its time, user, IP and outcome.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Everything "Not observable" | Capture started after the tunnel was up | Capture while the tunnel starts or rekeys |
| "IPsec not detected" | No IKE/ESP/AH in the file | Check the capture filter and interface |
| Traffic "unavailable" | Fewer than 10 ESP/AH packets | Capture longer |
| ESP cipher "undecided" | Fewer than 4 distinct ESP lengths | Capture more varied traffic |
| Upload rejected as not a capture | The file is not a pcap or pcapng (e.g. a renamed .etl) | Export as pcapng from Wireshark |
| Analysis failed: TShark | TShark missing or too old | Check `/health`; install Wireshark 4.x |
