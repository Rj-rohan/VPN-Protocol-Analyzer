import { Panel, SourceBadge } from "@/components/ui";
import type { InferredValue, ProtocolInference } from "@/types";

const METHODS: Record<string, string> = {
  "bayesian-lattice": "Bayesian length-lattice inference",
  "readable-payload": "payload readable (ESP-NULL)",
  "physical-bound": "physical size bound",
  "random-forest": "RandomForest on inner-packet sizes",
};

function Row({ title, value, observed }: { title: string; value?: InferredValue; observed?: string }) {
  if (!value) return null;
  const known = value.label !== null && value.confidence !== null;
  return (
    <tr>
      <td className="muted" style={{ width: 170 }}>{title}</td>
      <td>
        <strong>{known ? value.label : "Undecided"}</strong>
        {known && <span className="mono muted"> · {Math.round((value.confidence ?? 0) * 100)}%</span>}
        {observed && <div className="evidence">Parser: {observed}</div>}
      </td>
      <td><SourceBadge source={known ? "predicted" : "unavailable"} /></td>
      <td className="evidence">
        {METHODS[value.method] ?? value.method}
        {value.reason && <> · {value.reason}</>}
        {value.cv_accuracy != null && <> · cross-validated accuracy {Math.round(value.cv_accuracy * 100)}%</>}
        {value.key_length && <div>{value.key_length}</div>}
      </td>
    </tr>
  );
}

export default function InferencePanel({ inference, observedMode }: { inference?: ProtocolInference; observedMode: string }) {
  if (!inference) return null;
  return (
    <Panel title="AI protocol inference" aside={<span>from encrypted packet lengths</span>}>
      {inference.status !== "predicted" ? (
        <div className="empty">{inference.reason}</div>
      ) : (
        <>
          <div className="table-wrap"><table className="data">
            <thead><tr><th>Parameter</th><th>Prediction</th><th>Source</th><th>How</th></tr></thead>
            <tbody>
              <Row title="Tunnel / transport mode" value={inference.mode} observed={observedMode !== "Unknown" ? observedMode : undefined} />
              <Row title="ESP cipher family" value={inference.esp_cipher} />
            </tbody>
          </table></div>
          {inference.evidence && inference.evidence.length > 0 && (
            <ul className="evidence" style={{ margin: "12px 0 0", paddingLeft: 18 }}>{inference.evidence.map((line) => <li key={line}>{line}</li>)}</ul>
          )}
        </>
      )}
      <p className="note" style={{ marginTop: 12 }}>{inference.caveat}</p>
    </Panel>
  );
}
