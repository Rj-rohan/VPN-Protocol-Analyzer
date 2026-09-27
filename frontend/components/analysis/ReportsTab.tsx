"use client";

import { useEffect, useState } from "react";
import { ErrorBox, Loading, Panel, bytes, when } from "@/components/ui";
import { api } from "@/lib/api";
import type { Narrative, ReportInfo } from "@/types";

export default function ReportsTab({ analysisId, reports, onChange }: { analysisId: string; reports: ReportInfo[]; onChange: () => void }) {
  const [narrative, setNarrative] = useState<Narrative | null>(null);
  const [useLlm, setUseLlm] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setNarrative(null);
    api.narrative(analysisId, useLlm).then(setNarrative).catch((e) => setError(e.message));
  }, [analysisId, useLlm]);

  async function generate(kind: "executive" | "technical") {
    setBusy(kind);
    setError(null);
    try {
      const report = await api.createReport(analysisId, kind);
      onChange();
      await api.downloadReport(report, analysisId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report generation failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid" style={{ gap: 16 }}>
      <Panel title="Generate reports">
        <div className="row">
          <button className="btn" disabled={busy !== null} onClick={() => generate("executive")}>{busy === "executive" ? "Generating…" : "Generate Executive Report"}</button>
          <button className="btn" disabled={busy !== null} onClick={() => generate("technical")}>{busy === "technical" ? "Generating…" : "Generate Technical Report"}</button>
          <span className="muted" style={{ fontSize: 13 }}>PDF, downloaded automatically and kept below.</span>
        </div>
        <ErrorBox message={error} />
        {reports.length > 0 && (
          <table className="data" style={{ marginTop: 14 }}>
            <thead><tr><th>Report</th><th>Generated</th><th>Size</th><th>Narrative</th><th /></tr></thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td style={{ textTransform: "capitalize" }}>{r.kind}</td>
                  <td className="muted">{when(r.created_at)}</td>
                  <td className="num">{bytes(r.size_bytes)}</td>
                  <td className="evidence">{r.narrative_source}</td>
                  <td><button className="btn secondary small" onClick={() => api.downloadReport(r, analysisId).catch((e) => setError(e.message))}>Download PDF</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel
        title="Explanation"
        aside={
          <label className="row" style={{ fontSize: 12, textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" checked={useLlm} disabled={!narrative?.llm_available && !useLlm} onChange={(e) => setUseLlm(e.target.checked)} />
            AI narrative {narrative && !narrative.llm_available && "(not configured)"}
          </label>
        }
      >
        {!narrative ? <Loading label={useLlm ? "Asking the explanation model" : "Loading"} /> : (
          <div className="grid" style={{ gap: 14 }}>
            <div><div className="eyebrow">Executive summary</div><p className="prose">{narrative.narrative.executive_summary}</p></div>
            <div><div className="eyebrow">Technical explanation</div><p className="prose mono" style={{ fontSize: 12.5 }}>{narrative.narrative.technical_explanation}</p></div>
            {narrative.narrative.remediation.length > 0 && (
              <div><div className="eyebrow">Recommended remediation</div><ul className="prose">{narrative.narrative.remediation.map((r) => <li key={r}>{r}</li>)}</ul></div>
            )}
            <div><div className="eyebrow">Limitations</div><ul className="prose muted">{narrative.narrative.limitations.map((l) => <li key={l}>{l}</li>)}</ul></div>
            <p className="note">
              Source: {narrative.source}. The explanation layer only receives the structured analyzer output; any AI text that names a value
              not present in that output is rejected and the deterministic narrative is shown instead.
            </p>
          </div>
        )}
      </Panel>
    </div>
  );
}
