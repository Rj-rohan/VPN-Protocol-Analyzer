"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { CategoryDonut, SeverityBars } from "@/components/charts";
import { ErrorBox, Loading, PageHead, Panel, SeverityBadge, Stat, StatusBadge, when } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { DashboardSummary } from "@/types";

export default function Dashboard() {
  const { user } = useAuth();
  const router = useRouter();
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () => api.dashboard().then((d) => !cancelled && setData(d)).catch((e) => !cancelled && setError(e.message));
    load();
    const timer = setInterval(() => data?.pending_analyses && load(), 4000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [data?.pending_analyses]);

  const canUpload = user?.role !== "viewer";
  return (
    <>
      <PageHead
        eyebrow="SIH 26160 · Security overview"
        title="Dashboard"
        lede="Deterministic protocol evidence first; traffic categories are probabilistic predictions from encrypted-traffic metadata."
        actions={canUpload && <Link className="btn" href="/upload">Upload PCAP</Link>}
      />
      <ErrorBox message={error} />
      {!data && !error && <Loading />}
      {data && (
        <div className="grid" style={{ gap: 16 }}>
          <div className="grid cols-4">
            <Stat label="Total analyses" value={data.total_analyses} />
            <Stat label="IPsec detections" value={data.ipsec_detections} />
            <Stat label="High-risk captures" value={data.high_risk_captures} alert={data.high_risk_captures > 0} />
            <Stat label="Critical findings" value={data.critical_findings} alert={data.critical_findings > 0} />
          </div>
          <div className="grid cols-3">
            <Panel title="Risk distribution"><SeverityBars data={data.risk_distribution} /></Panel>
            <Panel title="Findings by severity"><SeverityBars data={data.findings_by_severity} /></Panel>
            <Panel title="Traffic categories" aside={<span>predicted</span>}><CategoryDonut data={data.traffic_categories} /></Panel>
          </div>
          <div className="grid cols-3">
            <Panel title="Recent analyses" className="span-2" aside={<Link href="/analyses" className="mono">View all →</Link>}>
              {data.recent.length === 0 ? (
                <div className="empty">No captures analyzed yet.{canUpload && <> <Link href="/upload" style={{ textDecoration: "underline" }}>Upload one</Link>.</>}</div>
              ) : (
                <div className="table-wrap">
                  <table className="data">
                    <thead><tr><th>Capture</th><th>Status</th><th>IKE</th><th>Score</th><th>Risk</th><th>Traffic</th><th>Uploaded</th></tr></thead>
                    <tbody>
                      {data.recent.map((a) => (
                        <tr key={a.analysis_id} className="clickable" onClick={() => router.push(`/analyses/${a.analysis_id}`)}>
                          <td className="mono">{a.filename}</td>
                          <td><StatusBadge status={a.status} /></td>
                          <td>{a.ike_version ?? "—"}</td>
                          <td className="num">{a.security_score ?? "—"}</td>
                          <td><SeverityBadge level={a.risk_level} /></td>
                          <td>{a.predicted_traffic ?? "—"}</td>
                          <td className="muted">{when(a.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
            <Panel title="Most frequent findings">
              {data.top_findings.length === 0 ? <div className="empty">No findings</div> : (
                <table className="data">
                  <tbody>
                    {data.top_findings.map((f) => (
                      <tr key={f.rule_id}><td className="mono id">{f.rule_id}</td><td>{f.title}</td><td className="num">{f.count}</td></tr>
                    ))}
                  </tbody>
                </table>
              )}
              {data.compliance && (
                <div style={{ marginTop: 16 }}>
                  <div className="eyebrow" style={{ color: "var(--muted)" }}>Compliance · {data.compliance.profile_name}</div>
                  <div className="row" style={{ marginTop: 8, gap: 8 }}>
                    <span className="badge st-completed">{data.compliance.verdicts["compliant"] ?? 0} compliant</span>
                    <span className="badge st-queued">{data.compliance.verdicts["insufficient evidence"] ?? 0} insufficient evidence</span>
                    <span className="badge st-failed">{data.compliance.verdicts["non-compliant"] ?? 0} non-compliant</span>
                  </div>
                  {data.compliance.top_failed_controls.length > 0 && (
                    <p className="evidence" style={{ marginTop: 8 }}>Most failed: {data.compliance.top_failed_controls.map((c) => `${c.id} ${c.title} (${c.count})`).join(" · ")}</p>
                  )}
                </div>
              )}
              <p className="muted" style={{ fontSize: 12.5, marginTop: 14 }}>
                Average Project Security Assessment Score: <strong>{data.average_score ?? "—"}</strong>
                {data.average_ai_confidence != null && <> · average AI confidence: <strong>{data.average_ai_confidence}</strong></>}
                {Object.keys(data.ike_versions).length > 0 && <> · IKE: {Object.entries(data.ike_versions).map(([v, n]) => `${v} (${n})`).join(", ")}</>}
              </p>
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}
