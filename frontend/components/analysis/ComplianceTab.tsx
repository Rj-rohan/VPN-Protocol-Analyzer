"use client";

import { useEffect, useState } from "react";
import { ErrorBox, Loading, Panel, SeverityBadge, SourceBadge, display } from "@/components/ui";
import { api } from "@/lib/api";
import type { ComplianceEvaluation } from "@/types";

const STATUS_LABEL = { pass: "Pass", fail: "Fail", unknown: "Not observable", not_applicable: "N/A" } as const;
const STATUS_CLASS = { pass: "st-completed", fail: "st-failed", unknown: "src-unavailable", not_applicable: "src-unavailable" } as const;
const VERDICT_COLOR = { compliant: "var(--good)", "non-compliant": "var(--critical)", "insufficient evidence": "var(--medium)" } as const;

export default function ComplianceTab({ analysisId }: { analysisId: string }) {
  const [evaluations, setEvaluations] = useState<Record<string, ComplianceEvaluation> | null>(null);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.compliance(analysisId).then((data) => {
      setEvaluations(data.evaluations);
      setSelected(data.evaluations[data.default] ? data.default : Object.keys(data.evaluations)[0] ?? "");
    }).catch((e) => setError(e.message));
  }, [analysisId]);

  if (error) return <ErrorBox message={error} />;
  if (!evaluations) return <Loading />;
  const current = evaluations[selected];

  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="grid cols-3">
        {Object.values(evaluations).map((e) => (
          <button key={e.profile.id} className="panel" onClick={() => setSelected(e.profile.id)}
            style={{ textAlign: "left", cursor: "pointer", outline: e.profile.id === selected ? "2px solid var(--ink)" : "none" }}>
            <div className="eyebrow" style={{ color: "var(--muted)" }}>{e.profile.name}</div>
            <div style={{ fontSize: 22, fontWeight: 600, margin: "8px 0", color: VERDICT_COLOR[e.verdict], textTransform: "capitalize" }}>{e.verdict}</div>
            <div className="mono muted" style={{ fontSize: 12 }}>
              {e.counts.pass} pass · {e.counts.fail} fail · {e.counts.unknown} not observable{e.counts.not_applicable ? ` · ${e.counts.not_applicable} n/a` : ""}
            </div>
          </button>
        ))}
      </div>
      {current && (
        <Panel title={`${current.profile.name} · controls`} aside={<span>{current.profile.reference}</span>}>
          <div className="table-wrap"><table className="data">
            <thead><tr><th>Control</th><th>Status</th><th>Severity</th><th>Observed</th><th>Evidence</th><th>Remediation</th></tr></thead>
            <tbody>
              {current.controls.map((c) => (
                <tr key={c.id}>
                  <td style={{ minWidth: 200 }}><div className="mono muted id">{c.id}</div><strong>{c.title}</strong><div className="evidence">{c.requirement}</div></td>
                  <td><span className={`badge ${STATUS_CLASS[c.status]}`}>{STATUS_LABEL[c.status]}</span>{c.basis && c.basis !== "unavailable" && <div style={{ marginTop: 4 }}><SourceBadge source={c.basis} /></div>}</td>
                  <td><SeverityBadge level={c.severity} /></td>
                  <td className="mono" style={{ maxWidth: 180 }}>{display(c.observed)}</td>
                  <td className="evidence" style={{ minWidth: 200 }}>{c.evidence}</td>
                  <td style={{ minWidth: 180, fontSize: 13 }}>{c.status === "fail" ? c.remediation : ""}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
          <p className="note" style={{ marginTop: 12 }}>
            {current.profile.disclaimer} &ldquo;Not observable&rdquo; controls (e.g. PFS or ESP key length) must be verified on the VPN endpoints;
            a profile is only reported compliant when every applicable control passes on evidence.
          </p>
        </Panel>
      )}
    </div>
  );
}
