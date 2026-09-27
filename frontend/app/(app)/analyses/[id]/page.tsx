"use client";

import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import ComplianceTab from "@/components/analysis/ComplianceTab";
import ProtocolTab from "@/components/analysis/ProtocolTab";
import ReportsTab from "@/components/analysis/ReportsTab";
import { SecurityTab, ThreatMatrix } from "@/components/analysis/SecurityTab";
import TrafficTab from "@/components/analysis/TrafficTab";
import { ErrorBox, Loading, PageHead, Panel, SeverityBadge, StatusBadge, bytes, when } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { AnalysisDetail, AnalysisResult } from "@/types";

const TABS = ["Protocol details", "Security assessment", "Compliance", "Threat matrix", "Traffic analysis", "Reports"] as const;

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const router = useRouter();
  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [tab, setTab] = useState<(typeof TABS)[number]>("Protocol details");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => api.analysis(id).then(setAnalysis).catch((e) => setError(e.message)), [id]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!analysis || !["queued", "running"].includes(analysis.status)) return;
    const timer = setTimeout(load, 2000);
    return () => clearTimeout(timer);
  }, [analysis, load]);

  async function remove() {
    if (!analysis || !confirm(`Delete the analysis of ${analysis.filename}? The stored capture and its reports are removed too.`)) return;
    try {
      await api.deleteAnalysis(analysis.analysis_id);
      router.replace("/analyses");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed.");
    }
  }

  if (error && !analysis) return <ErrorBox message={error} />;
  if (!analysis) return <Loading />;

  const result = analysis.status === "completed" ? (analysis.result as AnalysisResult) : null;
  const canDelete = user?.role === "admin" || (user?.role === "analyst" && analysis.owner === user.email);
  return (
    <>
      <PageHead
        eyebrow={`Analysis ${analysis.analysis_id.slice(0, 8)}`}
        title={analysis.filename}
        lede={`${bytes(analysis.capture.size_bytes)} · ${analysis.capture.file_format} · SHA-256 ${analysis.capture.sha256.slice(0, 16)}… · uploaded ${when(analysis.capture.uploaded_at)}${analysis.owner ? ` by ${analysis.owner}` : ""}`}
        actions={
          <>
            <StatusBadge status={analysis.status} />
            {analysis.risk_level && <SeverityBadge level={analysis.risk_level} />}
            {canDelete && <button className="btn danger small" onClick={remove}>Delete</button>}
          </>
        }
      />
      <ErrorBox message={error} />
      {analysis.warnings.length > 0 && <div className="note" style={{ marginBottom: 16 }}>Parser warnings: {analysis.warnings.join(" · ")}</div>}
      {analysis.status === "failed" && <Panel title="Analysis failed"><p>{analysis.error}</p></Panel>}
      {!result && analysis.status !== "failed" && <Panel title="Analysis in progress"><Loading label={`Status: ${analysis.status}`} /></Panel>}
      {result && (
        <>
          <nav className="tabs" role="tablist">
            {TABS.map((name) => (
              <button key={name} role="tab" aria-selected={tab === name} className={tab === name ? "active" : ""} onClick={() => setTab(name)}>{name}</button>
            ))}
          </nav>
          {tab === "Protocol details" && <ProtocolTab result={result} />}
          {tab === "Security assessment" && <SecurityTab result={result} />}
          {tab === "Compliance" && <ComplianceTab analysisId={analysis.analysis_id} />}
          {tab === "Threat matrix" && <ThreatMatrix result={result} />}
          {tab === "Traffic analysis" && <TrafficTab result={result} />}
          {tab === "Reports" && <ReportsTab analysisId={analysis.analysis_id} reports={analysis.reports} onChange={load} />}
        </>
      )}
    </>
  );
}
