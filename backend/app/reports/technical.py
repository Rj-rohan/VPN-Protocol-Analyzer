"""Technical report: full evidence for network security engineers."""
from reportlab.lib.units import mm
from reportlab.platypus import Spacer

from app.reports.pdf import bar_chart, bullets, key_values, p, render, score_block, table


def _obs_rows(section: dict, names: list[tuple[str, str]]) -> list[list[str]]:
    rows = [["Parameter", "Value", "Source", "Evidence"]]
    for key, label in names:
        item = section.get(key, {})
        value = item.get("value")
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        elif value is True or value is False:
            value = "Yes" if value else "No"
        rows.append([label, str(value), item.get("source", ""), "; ".join(item.get("evidence", []))])
    return rows


def _accuracy_text(model: dict) -> str:
    """Cross-validated accuracy (every capture held out once); the single hold-out split only for older models."""
    if model.get("cv_accuracy") is None:
        return f"held-out test accuracy {(model.get('test_metrics') or {}).get('accuracy', 0):.3f}"
    by_source = model.get("cv_accuracy_by_source") or {}
    real_apps = next((v for k, v in by_source.items() if k.startswith("iscx_vpn")), None)
    return (f"cross-validated accuracy {model['cv_accuracy']:.1%}"
            + (f" ({real_apps:.1%} on real-application captures)" if real_apps is not None else ""))


def build(f: dict, narrative: dict, narrative_source: str, meta: dict, result: dict) -> bytes:
    features = result.get("features", {})
    detection, protocol, crypto, sa = features.get("detection", {}), features.get("protocol", {}), features.get("cryptography", {}), features.get("sa", {})
    stats, replay, traffic = features.get("packet_statistics", {}), features.get("replay_indicators", {}), features.get("traffic", {})
    tf = traffic.get("features", {})
    prediction = result.get("traffic_prediction") or {}
    widths = [34 * mm, 38 * mm, 20 * mm, 78 * mm]

    story = [
        p("Capture Information", "h1"),
        key_values([("File", meta["filename"]), ("SHA-256", meta["sha256"]), ("Size", f"{meta['size_bytes']:,} bytes"),
                    ("Analysis ID", meta["analysis_id"]), ("Analyzed", meta["completed_at"]), ("Parser", result.get("tshark_version") or "TShark"),
                    ("Parser warnings", "; ".join(result.get("warnings") or []) or "None")]),
        p("Packet Statistics", "h1"),
        table([["Total", "IKE messages", "ESP", "UDP-encapsulated ESP", "AH"],
               [stats.get("packet_count", 0), stats.get("ike_message_count", 0), stats.get("esp_packet_count", 0),
                stats.get("udp_encapsulated_esp_count", 0), stats.get("ah_packet_count", 0)]], [34 * mm] * 5),
        p(f"Detection: IPsec {'detected' if detection.get('ipsec_detected') else 'not detected'}; confidence {detection.get('confidence', 0):.2f} "
          f"({detection.get('confidence_method', '')}). Evidence: {'; '.join(detection.get('evidence', [])) or 'none'}.", "small"),
        p("IKE Analysis", "h1"),
        table(_obs_rows(protocol, [("ike_version", "IKE version"), ("ike_exchange_types", "Exchanges"), ("ip_version", "IP version")]), widths),
        p("Proposals", "h2"),
    ]
    proposals = features.get("ike_proposals", {})
    rows = [["Role", "Protocol", "Encryption", "Integrity / PRF", "DH"]]
    for role in ("selected", "offered"):
        for item in proposals.get(role, []):
            rows.append([role, item.get("protocol", ""), ", ".join(item.get("encryption", [])),
                         ", ".join(item.get("integrity", []) + item.get("prf", [])), ", ".join(item.get("dh", []))])
    story.append(table(rows, [20 * mm, 18 * mm, 45 * mm, 50 * mm, 37 * mm]) if len(rows) > 1 else p("No cleartext SA proposal was captured."))
    story += [
        p("ESP Analysis and IPsec Mode", "h1"),
        table(_obs_rows({"mode": features.get("mode", {}), **sa}, [("mode", "Mode"), ("payload_confidentiality", "Payload encrypted"),
                                                                    ("spi_values", "SPI values"), ("nat_traversal", "NAT-T")]), widths),
    ]
    inference = result.get("protocol_inference") or {}
    story.append(p("AI Protocol Inference", "h2"))
    if inference.get("status") == "predicted":
        rows = [["Parameter", "Prediction", "Confidence", "Method"]]
        for title, key in (("Tunnel / transport mode", "mode"), ("ESP cipher family", "esp_cipher")):
            entry = inference.get(key) or {}
            rows.append([title, entry.get("label") or "Undecided",
                         f"{entry['confidence']:.0%}" if entry.get("confidence") is not None else "n/a",
                         entry.get("reason") or entry.get("method", "")])
        story += [table(rows, [38 * mm, 58 * mm, 20 * mm, 54 * mm]),
                  p(" ".join(inference.get("evidence", [])), "small"),
                  p(f"{inference.get('caveat', '')} {(inference.get('esp_cipher') or {}).get('key_length', '')}", "small")]
    else:
        story.append(p(f"No prediction: {inference.get('reason', 'not available')}.", "small"))
    story += [
        p("Cryptographic Configuration", "h1"),
        p(f"Scope: {crypto.get('scope', '')}. ESP child SA transforms are negotiated inside encrypted IKE messages.", "small"),
        table(_obs_rows(crypto, [("encryption_algorithm", "Encryption"), ("integrity_algorithm", "Integrity"), ("prf_algorithm", "PRF"),
                                 ("authentication_method", "Authentication")]), widths),
        p("DH / PFS", "h1"),
        table(_obs_rows(crypto, [("dh_group", "DH group"), ("pfs", "PFS")]), widths),
        p("SA Characteristics and Replay Protection", "h1"),
        table(_obs_rows(sa, [("sa_lifetime_seconds", "SA lifetime (s)"), ("ike_rekey_interval_seconds", "IKE SA rekey interval (s)"),
                             ("child_rekey_interval_seconds", "Child SA rekey interval (s)"), ("replay_protection", "Replay protection")]), widths),
        Spacer(1, 3),
        table([["SPIs", "Packets with sequence numbers", "Strictly increasing SPIs", "Duplicates", "Out of order"],
               [replay.get("spi_count", 0), replay.get("packets_with_sequence_numbers", 0), replay.get("spis_with_strictly_increasing_sequences", 0),
                replay.get("duplicate_sequence_numbers", 0), replay.get("out_of_order_sequence_numbers", 0)]], [34 * mm] * 5),
        p("Traffic Classification", "h1"),
        key_values([("ESP/AH packets", tf.get("flow_packet_count", 0)), ("Duration", f"{tf.get('duration_seconds', 0):.2f} s"),
                    ("Packet rate", f"{tf.get('packets_per_second', 0):.2f} packets/s"),
                    ("Packet size (avg / std)", f"{tf.get('avg_packet_size_bytes', 0):.1f} / {tf.get('std_packet_size_bytes', 0):.1f} bytes"),
                    ("Inter-arrival (avg / p50)", f"{tf.get('avg_interarrival_ms', 0):.2f} / {tf.get('p50_interarrival_ms', 0):.2f} ms"),
                    ("Bytes up / down", f"{tf.get('bytes_up', 0):,} / {tf.get('bytes_down', 0):,} ({traffic.get('direction_basis', '')})"),
                    ("Bursts", f"{tf.get('burst_count', 0)} (avg {tf.get('avg_burst_packets', 0):.1f}, max {tf.get('max_burst_packets', 0)} packets)")]),
    ]
    histogram = traffic.get("size_histogram", [])
    if histogram and tf.get("flow_packet_count", 0):
        story.append(bar_chart([bucket["range"] for bucket in histogram], [bucket["packets"] for bucket in histogram], "Packet size distribution (bytes)"))
    story.append(p("ML Confidence", "h2"))
    if prediction.get("status") == "predicted":
        model = prediction.get("model", {})
        story += [
            table([["Category", "Probability"]] + [[label, f"{value:.1%}"] for label, value in list(prediction["probabilities"].items())[:7]], [60 * mm, 40 * mm]),
            p(f"Model: {model.get('name')} {model.get('version')} trained on {model.get('training_source')}; {_accuracy_text(model)}. "
              f"{prediction.get('caveat', '')}", "small"),
        ]
    else:
        story.append(p(f"No prediction: {prediction.get('reason', 'not available')}."))

    assessment = f["assessment"]
    story += [p("Security Findings", "h1"), score_block(assessment["security_score"], assessment["risk_level"]), Spacer(1, 4)]
    if f["findings"]:
        story.append(table([["Rule", "Severity", "Finding", "Evidence", "Impact"]] +
                           [[x["rule_id"], x["severity"], x["title"], x["evidence"], x["impact"]] for x in f["findings"]],
                           [24 * mm, 17 * mm, 32 * mm, 52 * mm, 45 * mm]))
    else:
        story.append(p("No rule was triggered."))
    confidence = result.get("ai_confidence") or {}
    if confidence.get("components"):
        story += [p("AI Confidence Score", "h1"),
                  p(f"Overall {confidence['score']}/100. {confidence.get('method', '')}", "small"),
                  table([["Component", "Score", "Basis", "Explanation"]] +
                        [[c["name"], f"{c['value']:.0%}", c["basis"], c["explanation"]] for c in confidence["components"]],
                        [42 * mm, 16 * mm, 20 * mm, 92 * mm])]
    compliance = result.get("compliance") or {}
    if compliance:
        from app.config import settings

        story += [p("Configuration Compliance", "h1"),
                  table([["Standard / policy", "Verdict", "Pass", "Fail", "Not observable", "N/A"]] +
                        [[e["profile"]["name"], e["verdict"].capitalize(), e["counts"]["pass"], e["counts"]["fail"],
                          e["counts"]["unknown"], e["counts"]["not_applicable"]] for e in compliance.values()],
                        [62 * mm, 32 * mm, 16 * mm, 16 * mm, 26 * mm, 18 * mm])]
        detail = compliance.get(settings.default_compliance_profile) or next(iter(compliance.values()))
        labels = {"pass": "Pass", "fail": "FAIL", "unknown": "Not observable", "not_applicable": "N/A"}
        story += [p(f"{detail['profile']['name']}: controls", "h2"),
                  table([["Control", "Requirement", "Status", "Basis", "Observed"]] +
                        [[c["id"], c["title"], labels[c["status"]], c["basis"] or "", str(c["observed"]) if c["observed"] is not None else "-"]
                         for c in detail["controls"]], [20 * mm, 60 * mm, 24 * mm, 22 * mm, 44 * mm]),
                  p(detail["profile"]["disclaimer"] + " Reference: " + detail["profile"]["reference"] + ".", "small")]
    story += [p("Analysis", "h1"), p(narrative["technical_explanation"]),
              p("Recommendations", "h1"), *(bullets(narrative["remediation"]) or [p("None.")]),
              p("Limitations", "h1"), *bullets(narrative.get("limitations", [])),
              Spacer(1, 6), p(f"Narrative source: {narrative_source}. Scoring methodology: "
                              f"{result.get('security', {}).get('assessment', {}).get('methodology', {}).get('formula', '')}.", "small")]
    subtitle = [f"Capture: {meta['filename']}  |  SHA-256: {meta['sha256'][:32]}...", f"Analysis ID: {meta['analysis_id']}  |  Analyzed: {meta['completed_at']}"]
    return render("IPsec Security Assessment: Technical Report", subtitle, story)
