import ConfidencePanel from "@/components/analysis/ConfidencePanel";
import { SeverityBars } from "@/components/charts";
import { Panel, SEVERITIES, SEVERITY_COLORS, SeverityBadge, SourceBadge } from "@/components/ui";
import type { AnalysisResult } from "@/types";

export function SecurityTab({ result }: { result: AnalysisResult }) {
  const { assessment, findings } = result.security;
  const color = SEVERITY_COLORS[assessment.risk_level];
  return (
    <div className="grid" style={{ gap: 16 }}>
      <ConfidencePanel confidence={result.ai_confidence} />
      <div className="grid cols-3">
        <Panel title={assessment.score_name}>
          <div className="score"><strong>{assessment.security_score}</strong><span>/ 100</span></div>
          <div className="meter"><div style={{ width: `${assessment.security_score}%`, background: color }} /></div>
          <div className="row"><SeverityBadge level={assessment.risk_level} /><span className="muted" style={{ fontSize: 13 }}>{assessment.finding_count} finding(s)</span></div>
          <p className="muted" style={{ fontSize: 12, marginTop: 14 }}>{assessment.methodology.disclaimer}</p>
        </Panel>
        <Panel title="Findings by severity">
          <SeverityBars data={{ Critical: assessment.critical_count, High: assessment.high_count, Medium: assessment.medium_count, Low: assessment.low_count }} />
        </Panel>
        <Panel title="Methodology">
          <p className="mono" style={{ fontSize: 12.5 }}>{assessment.methodology.formula}</p>
          <table className="data">
            <tbody>
              {SEVERITIES.map((s) => (
                <tr key={s}><td><SeverityBadge level={s} /></td><td className="num">−{assessment.methodology.penalties[s]} each</td><td className="evidence">{assessment.methodology.thresholds[s]}</td></tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
      <Panel title="Findings">
        {findings.length === 0 ? <div className="empty">No rule was triggered by the observable parameters.</div> : (
          <div className="grid" style={{ gap: 12 }}>
            {findings.map((f) => (
              <article key={f.rule_id} style={{ borderLeft: `3px solid ${SEVERITY_COLORS[f.severity]}`, paddingLeft: 14 }}>
                <div className="row"><SeverityBadge level={f.severity} /><span className="mono">{f.rule_id}</span><strong>{f.title}</strong><SourceBadge source={f.source} /></div>
                <p style={{ margin: "6px 0", fontSize: 14 }}>{f.description}</p>
                <p className="evidence" style={{ margin: 0 }}><strong>Condition:</strong> {f.condition} · <strong>Evidence:</strong> {f.evidence}</p>
              </article>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

export function ThreatMatrix({ result }: { result: AnalysisResult }) {
  const findings = result.security.findings;
  return (
    <Panel title="Threat matrix" aside={<span>{findings.length} finding(s)</span>}>
      {findings.length === 0 ? <div className="empty">No threats identified from the observable configuration.</div> : (
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Finding</th><th>Severity</th><th>Evidence</th><th>Impact</th><th>Recommendation</th></tr></thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.rule_id}>
                  <td style={{ minWidth: 170 }}><div className="mono muted">{f.rule_id}</div><strong>{f.title}</strong></td>
                  <td><SeverityBadge level={f.severity} /></td>
                  <td className="evidence" style={{ minWidth: 220 }}>{f.evidence}</td>
                  <td style={{ minWidth: 200, fontSize: 13 }}>{f.impact}</td>
                  <td style={{ minWidth: 220, fontSize: 13 }}>{f.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
