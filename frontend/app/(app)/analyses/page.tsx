"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ErrorBox, Loading, PageHead, Panel, SeverityBadge, StatusBadge, when } from "@/components/ui";
import { api } from "@/lib/api";
import type { AnalysisSummary } from "@/types";

const PAGE = 20;

export default function AnalysesPage() {
  const router = useRouter();
  const [items, setItems] = useState<AnalysisSummary[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [risk, setRisk] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setItems(null);
    api.analyses({ limit: PAGE, offset, risk, status })
      .then((page) => { setItems(page.items); setTotal(page.total); })
      .catch((e) => setError(e.message));
  }, [offset, risk, status]);

  return (
    <>
      <PageHead eyebrow="Evidence archive" title="Analyses" lede="Every analyzed capture you are permitted to see." />
      <Panel
        title={`${total} analyses`}
        aside={
          <div className="filters">
            <select className="input" value={risk} onChange={(e) => { setOffset(0); setRisk(e.target.value); }} aria-label="Risk">
              <option value="">All risk levels</option>
              {["Critical", "High", "Medium", "Low"].map((r) => <option key={r}>{r}</option>)}
            </select>
            <select className="input" value={status} onChange={(e) => { setOffset(0); setStatus(e.target.value); }} aria-label="Status">
              <option value="">All statuses</option>
              {["completed", "running", "queued", "failed"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>
        }
      >
        <ErrorBox message={error} />
        {!items ? <Loading /> : items.length === 0 ? <div className="empty">Nothing matches these filters.</div> : (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Capture</th><th>Status</th><th>Packets</th><th>Protocols</th><th>IKE</th><th>Score</th><th>Risk</th><th>Traffic</th><th>Owner</th><th>Uploaded</th></tr></thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.analysis_id} className="clickable" onClick={() => router.push(`/analyses/${a.analysis_id}`)}>
                    <td className="mono">{a.filename}</td>
                    <td><StatusBadge status={a.status} /></td>
                    <td className="num">{a.packet_count.toLocaleString()}</td>
                    <td className="mono">{a.detected_protocols.join(" · ") || "—"}</td>
                    <td>{a.ike_version ?? "—"}</td>
                    <td className="num">{a.security_score ?? "—"}</td>
                    <td><SeverityBadge level={a.risk_level} /></td>
                    <td>{a.predicted_traffic ?? "—"}</td>
                    <td className="muted">{a.owner ?? "—"}</td>
                    <td className="muted">{when(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="row" style={{ marginTop: 14 }}>
          <span className="muted mono">{total ? `${offset + 1}–${Math.min(offset + PAGE, total)} of ${total}` : ""}</span>
          <span className="spacer" />
          <button className="btn secondary small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
          <button className="btn secondary small" disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>Next</button>
        </div>
      </Panel>
    </>
  );
}
