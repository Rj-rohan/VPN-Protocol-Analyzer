import { Panel } from "@/components/ui";
import type { AiConfidence } from "@/types";

const color = (value: number) => (value >= 0.8 ? "var(--good)" : value >= 0.5 ? "var(--medium)" : "var(--critical)");

export default function ConfidencePanel({ confidence }: { confidence?: AiConfidence }) {
  if (!confidence || confidence.score === null) return null;
  return (
    <Panel title="AI confidence score" aside={<span>how much rests on solid evidence</span>}>
      <div className="grid" style={{ gridTemplateColumns: "160px 1fr", gap: 24, alignItems: "start" }}>
        <div>
          <div className="score"><strong>{confidence.score}</strong><span>/ 100</span></div>
          <div className="meter"><div style={{ width: `${confidence.score}%`, background: color(confidence.score / 100) }} /></div>
        </div>
        <div className="grid" style={{ gap: 10 }}>
          {confidence.components.map((c) => (
            <div key={c.name}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <strong style={{ fontSize: 14 }}>{c.name}</strong>
                <span className="mono">{Math.round(c.value * 100)}% · {c.basis}</span>
              </div>
              <div className="meter" style={{ height: 6, margin: "5px 0" }}><div style={{ width: `${c.value * 100}%`, background: color(c.value) }} /></div>
              <div className="evidence">{c.explanation}</div>
            </div>
          ))}
        </div>
      </div>
      <p className="note" style={{ marginTop: 12 }}>{confidence.method}</p>
    </Panel>
  );
}
