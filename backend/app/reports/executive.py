"""Executive report: deployment posture for a manager."""
from reportlab.lib.units import mm
from reportlab.platypus import Spacer

from app.reports.pdf import bullets, key_values, p, render, score_block, table


def build(f: dict, narrative: dict, narrative_source: str, meta: dict) -> bytes:
    cfg, assessment, traffic = f["configuration"], f["assessment"], f["traffic"]
    key_findings = [x for x in f["findings"] if x["severity"] in ("Critical", "High")] or f["findings"][:3]
    story = [
        p("Executive Summary", "h1"),
        p(narrative["executive_summary"]),
        p("Overall Risk", "h1"),
        score_block(assessment["security_score"], assessment["risk_level"]),
        Spacer(1, 4),
        table([["Critical", "High", "Medium", "Low", "AI confidence"],
               [assessment["critical_count"], assessment["high_count"], assessment["medium_count"], assessment["low_count"],
                f"{f['ai_confidence']['score']}/100" if f.get("ai_confidence", {}).get("score") is not None else "n/a"]],
              [34 * mm] * 5),
        p("AI confidence: how much of this assessment rests on solid evidence (observed values, and ML predictions discounted by their "
          "measured accuracy). Parameters hidden by encryption lower it.", "small"),
        p("Key Findings", "h1"),
    ]
    if key_findings:
        story.append(table([["Severity", "Finding", "Business impact"]] + [[x["severity"], x["title"], x["impact"]] for x in key_findings],
                           [22 * mm, 55 * mm, 93 * mm]))
    else:
        story.append(p("No weaknesses were found in the parameters visible in this capture."))
    story += [
        p("Cryptographic Configuration", "h1"),
        key_values([
            ("IPsec protocol", cfg["ipsec_protocol"]["value"]),
            ("Key exchange", cfg["ike_version"]["value"]),
            ("Encryption (IKE SA)", cfg["encryption"]["value"]),
            ("Integrity (IKE SA)", cfg["integrity"]["value"]),
            ("Diffie-Hellman group", cfg["dh_group"]["value"]),
            ("Perfect forward secrecy", _with_source(cfg["pfs"])),
            ("Tunnel / transport mode", _with_prediction(cfg["mode"]["value"], f.get("ai_inference", {}).get("mode", {}))),
            ("ESP cipher family (AI-predicted)", _prediction_text(f.get("ai_inference", {}).get("esp_cipher", {}))),
            ("Payload encrypted", cfg["payload_confidentiality"]["value"]),
        ]),
    ]
    if f.get("compliance"):
        story += [p("Configuration Compliance", "h1"),
                  table([["Standard / policy", "Verdict", "Pass", "Fail", "Not observable"]] +
                        [[c["profile"], c["verdict"].capitalize(), c["counts"]["pass"], c["counts"]["fail"], c["counts"]["unknown"]]
                         for c in f["compliance"].values()], [70 * mm, 36 * mm, 20 * mm, 20 * mm, 24 * mm]),
                  p("Checks derived from the referenced guidance; not a certification. Controls that are not observable in traffic "
                    "must be verified on the VPN endpoints.", "small")]
    story += [p("Traffic Summary", "h1")]
    if traffic["prediction_status"] == "predicted":
        story.append(p(f"{traffic['esp_packets']} encrypted packets over {traffic['duration_seconds']} seconds. The traffic pattern most resembles "
                       f"{traffic['predicted_category']} (model probability {traffic['prediction_confidence']:.0%}). This is a statistical "
                       "inference from packet sizes and timing; the traffic itself was not decrypted."))
    else:
        story.append(p(f"{traffic['esp_packets']} encrypted packets observed. No traffic category was predicted for this capture."))
    story += [p("Top Recommendations", "h1"), *(bullets(narrative["remediation"][:5]) or [p("No remediation required for the observed parameters.")]),
              p("Limitations", "h1"), *bullets(narrative.get("limitations", [])),
              Spacer(1, 6), p(f"Narrative source: {narrative_source}. All configuration values come from the deterministic parser and rule engine.", "small")]
    return render("IPsec Security Assessment: Executive Report", _subtitle(meta), story)


def _prediction_text(entry: dict) -> str:
    return f"{entry['value']} ({entry['confidence']:.0%} model confidence)" if entry.get("value") else "Undecided"


def _with_source(entry: dict) -> str:
    # Inferred values (e.g. PFS from rekey sizes) say so, so readers do not take them as read off the wire.
    return f"{entry['value']} (inferred from rekeys)" if entry.get("source") == "inferred" else entry["value"]


def _with_prediction(observed: str, entry: dict) -> str:
    if observed not in ("Unknown", "Unknown / Not observable") or not entry.get("value"):
        return observed
    return f"{observed} (AI prediction: {entry['value']}, {entry['confidence']:.0%})"


def _subtitle(meta: dict) -> list[str]:
    return [f"Capture: {meta['filename']}  |  SHA-256: {meta['sha256'][:32]}...", f"Analysis ID: {meta['analysis_id']}  |  Analyzed: {meta['completed_at']}"]
