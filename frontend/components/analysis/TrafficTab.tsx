import { ProbabilityBars, SizeHistogram, TrafficTimeline } from "@/components/charts";
import { Panel, SourceBadge, bytes } from "@/components/ui";
import type { AnalysisResult, Prediction } from "@/types";

const pct = (value: number) => `${(value * 100).toFixed(1)}%`;

// Cross-validated accuracy (every capture held out once) is the reported figure; older models only have the single hold-out split.
function accuracyText(model: Prediction["model"]): string {
  if (model?.cv_accuracy == null) return `held-out test accuracy ${model?.test_metrics.accuracy != null ? pct(model.test_metrics.accuracy) : "n/a"}`;
  const realApps = Object.entries(model.cv_accuracy_by_source ?? {}).find(([source]) => source.startsWith("iscx_vpn"))?.[1];
  return `cross-validated accuracy ${pct(model.cv_accuracy)}${realApps != null ? ` (${pct(realApps)} on real-application captures)` : ""}`;
}

export default function TrafficTab({ result }: { result: AnalysisResult }) {
  const traffic = result.features.traffic;
  const f = traffic.features;
  const prediction = result.traffic_prediction;
  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="grid cols-4">
        <div className="panel stat">
          <span className="eyebrow" style={{ color: "var(--muted)" }}>Predicted traffic</span>
          <strong>{prediction?.status === "predicted" ? prediction.label : "—"}</strong>
          <span><SourceBadge source={prediction?.status === "predicted" ? "predicted" : "unavailable"} /></span>
        </div>
        <div className="panel stat">
          <span className="eyebrow" style={{ color: "var(--muted)" }}>Model confidence</span>
          <strong>{prediction?.confidence != null ? `${Math.round(prediction.confidence * 100)}%` : "—"}</strong>
          <span>class probability, uncalibrated</span>
        </div>
        <div className="panel stat"><span className="eyebrow" style={{ color: "var(--muted)" }}>Packet rate</span><strong>{f.packets_per_second.toFixed(1)}</strong><span>ESP/AH packets per second</span></div>
        <div className="panel stat">
          <span className="eyebrow" style={{ color: "var(--muted)" }}>Upload / download</span>
          <strong>{Math.round(f.uplink_ratio * 100)}% / {Math.round((1 - f.uplink_ratio) * 100)}%</strong>
          <span>{bytes(f.bytes_up)} up · {bytes(f.bytes_down)} down</span>
        </div>
      </div>

      <div className="grid cols-2">
        <Panel title="Class probabilities">
          {prediction?.status === "predicted" && prediction.probabilities ? (
            <>
              <ProbabilityBars data={prediction.probabilities} />
              <p className="evidence" style={{ marginTop: 10 }}>
                {prediction.model?.name} {prediction.model?.version} · trained on {prediction.model?.training_source} · {accuracyText(prediction.model)}
              </p>
            </>
          ) : <div className="empty">{prediction?.reason ?? "No prediction available."}</div>}
          <p className="note" style={{ marginTop: 12 }}>{prediction?.caveat}</p>
        </Panel>
        <Panel title="Packet size distribution" aside={<span>bytes</span>}>
          {f.flow_packet_count ? <SizeHistogram data={traffic.size_histogram} /> : <div className="empty">No ESP/AH packets.</div>}
        </Panel>
      </div>

      <Panel title="Timeline" aside={<span>{traffic.direction_basis}</span>}>
        {traffic.timeline.length ? <TrafficTimeline data={traffic.timeline} /> : <div className="empty">No ESP/AH packets.</div>}
      </Panel>

      <Panel title="Encrypted-traffic metadata" aside={<span>{traffic.scope}</span>}>
        <div className="kv">
          <div>ESP/AH packets</div><div>{f.flow_packet_count.toLocaleString()} ({f.packets_up} up, {f.packets_down} down)</div>
          <div>Duration</div><div>{f.duration_seconds.toFixed(2)} s</div>
          <div>Packet size</div><div>avg {f.avg_packet_size_bytes.toFixed(1)} · std {f.std_packet_size_bytes.toFixed(1)} · p10/p50/p90 {f.p10_packet_size_bytes.toFixed(0)}/{f.p50_packet_size_bytes.toFixed(0)}/{f.p90_packet_size_bytes.toFixed(0)} bytes</div>
          <div>Inter-arrival</div><div>avg {f.avg_interarrival_ms.toFixed(2)} · std {f.std_interarrival_ms.toFixed(2)} · p50 {f.p50_interarrival_ms.toFixed(2)} ms</div>
          <div>Bursts</div><div>{f.burst_count} bursts · avg {f.avg_burst_packets.toFixed(1)} · max {f.max_burst_packets} packets</div>
          <div>Direction changes</div><div>{f.direction_changes} ({(f.direction_change_rate * 100).toFixed(1)}% of transitions)</div>
        </div>
      </Panel>
    </div>
  );
}
