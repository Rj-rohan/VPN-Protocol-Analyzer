# Documentation

Technical documentation for the **AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework** (Smart India Hackathon, problem statement 26160).

| Document | For | Contents |
|---|---|---|
| [understanding_1.md](understanding_1.md) | Everyone, especially newcomers | Plain-language guide to part (a) of the problem statement: tunnel vs transport, AES, GCM vs CBC, DH groups, PFS, IPv4/IPv6, traffic types, and what the testbed covers |
| [understanding_2.md](understanding_2.md) | Everyone, especially newcomers | Plain-language guide to part (b): capture tools (tcpdump, Wireshark, our live capture) and the IKE, ESP, AH and normal traffic in the dataset |
| [understanding_3.md](understanding_3.md) | Everyone, especially newcomers | Plain-language guide to parts (c), (d), (e) and the deliverables: AI identification, security assessment, outputs, and what was built for each |
| [user-guide.md](user-guide.md) | Analysts, reviewers | Capturing, uploading, reading every tab, live capture, reports, troubleshooting |
| [architecture.md](architecture.md) | Developers | Components, pipeline, request and live-capture flows, data model, design decisions |
| [methodology.md](methodology.md) | Security engineers, judges | What a capture can reveal, source labels, the parser, rekey/PFS inference, AI inference, confidence scoring |
| [security-rules-and-compliance.md](security-rules-and-compliance.md) | Security engineers, auditors | The 14 rules, the score formula, the three compliance profiles and how to write your own |
| [model-card.md](model-card.md) | ML reviewers | Traffic classifier, mode and cipher inference: data, evaluation protocol, results, limitations |
| [evaluation.md](evaluation.md) | Everyone | Results against labelled strongSwan captures and how to reproduce them |
| [dataset.md](dataset.md) | Researchers | Dataset card for the released package: sources, labels, splits, licensing |
| [api.md](api.md) | Integrators | Every endpoint, roles, request and response shapes, error codes |
| [deployment.md](deployment.md) | Operators | Docker and native setup, every configuration variable, operations, production checklist |
| [application-security.md](application-security.md) | Security reviewers | Threat model and controls of the analyzer itself |
| [../testbed/README.md](../testbed/README.md) | Developers | strongSwan Docker testbed and WSL netns session recorder |

## The problem in one paragraph

Organisations run IPsec VPNs whose real configuration drifts from policy: legacy IKEv1, weak Diffie-Hellman groups, missing PFS, NULL encryption. Checking means logging into every gateway. A packet capture already holds much of the answer. The cleartext IKE negotiation shows the cryptography, and the sizes and timing of encrypted ESP packets reveal the mode, the cipher family and what kind of traffic the tunnel carries. This project turns a capture into an evidence-labelled configuration report, a security score, compliance results against NIST, CNSA or your own policy, and executive and technical PDFs, without decrypting anything.

## Principles

1. **Evidence before inference.** Every value says whether it was observed, inferred or predicted, with the evidence.
2. **Unknown is an answer.** Values hidden by encryption are reported as not observable, never guessed silently.
3. **Measured, not claimed.** Every accuracy figure comes from held-out groups of real captures, and the numbers are reproducible from the repository.
4. **AI explains, it does not invent.** The LLM narrative is grounded in the analyzer's facts, and a check rejects anything else.
