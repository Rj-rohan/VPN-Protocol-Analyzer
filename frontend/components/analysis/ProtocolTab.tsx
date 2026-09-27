import InferencePanel from "@/components/analysis/InferencePanel";
import { Panel, SourceBadge, display } from "@/components/ui";
import type { AnalysisResult, Observation } from "@/types";

function Row({ label, observation }: { label: string; observation: Observation | undefined }) {
  if (!observation) return null;
  return (
    <tr>
      <td style={{ width: 170 }} className="muted">{label}</td>
      <td style={{ fontWeight: 500 }}>{display(observation.value)}</td>
      <td><SourceBadge source={observation.source} /></td>
      <td className="evidence">{observation.evidence?.join(" · ")}</td>
    </tr>
  );
}

export default function ProtocolTab({ result }: { result: AnalysisResult }) {
  const { detection, protocol, mode, cryptography: crypto, sa, packet_statistics: stats, ike_proposals: proposals } = result.features;
  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="grid cols-4">
        <div className="panel stat"><span className="eyebrow" style={{ color: "var(--muted)" }}>IPsec</span><strong>{detection.ipsec_detected ? "Detected" : "Not detected"}</strong></div>
        <div className="panel stat"><span className="eyebrow" style={{ color: "var(--muted)" }}>Protocol</span><strong>{protocol.ipsec_protocol.replace("Unknown / Not observable", "—")}</strong></div>
        <div className="panel stat"><span className="eyebrow" style={{ color: "var(--muted)" }}>IKE version</span><strong>{display(protocol.ike_version.value).replace("Unknown / Not observable", "—")}</strong></div>
        <div className="panel stat">
          <span className="eyebrow" style={{ color: "var(--muted)" }}>Detection confidence</span>
          <strong>{Math.round(detection.confidence * 100)}%</strong>
          <span title={detection.confidence_method}>evidence-weighted heuristic</span>
        </div>
      </div>

      <Panel title="Protocol & encapsulation">
        <div className="table-wrap"><table className="data">
          <thead><tr><th>Parameter</th><th>Value</th><th>Source</th><th>Evidence</th></tr></thead>
          <tbody>
            <Row label="IKE version" observation={protocol.ike_version} />
            <Row label="IKE exchanges" observation={protocol.ike_exchange_types} />
            <Row label="Mode" observation={mode} />
            <Row label="IP version" observation={protocol.ip_version} />
            <Row label="NAT-T" observation={sa.nat_traversal} />
            <Row label="Payload encrypted" observation={sa.payload_confidentiality} />
            <Row label="SPI values" observation={sa.spi_values} />
          </tbody>
        </table></div>
      </Panel>

      <InferencePanel inference={result.protocol_inference} observedMode={String(mode.value)} />

      <Panel title="Cryptographic configuration" aside={<span>scope: {crypto.scope}</span>}>
        <div className="table-wrap"><table className="data">
          <thead><tr><th>Parameter</th><th>Value</th><th>Source</th><th>Evidence</th></tr></thead>
          <tbody>
            <Row label="Encryption" observation={crypto.encryption_algorithm} />
            <Row label="Integrity" observation={crypto.integrity_algorithm} />
            <Row label="PRF" observation={crypto.prf_algorithm} />
            <Row label="Authentication" observation={crypto.authentication_method} />
            <Row label="DH group" observation={crypto.dh_group} />
            <Row label="PFS" observation={crypto.pfs} />
            <Row label="SA lifetime (s)" observation={sa.sa_lifetime_seconds} />
            {sa.ike_rekey_interval_seconds && <Row label="IKE SA rekey interval (s)" observation={sa.ike_rekey_interval_seconds} />}
            {sa.child_rekey_interval_seconds && <Row label="Child SA rekey interval (s)" observation={sa.child_rekey_interval_seconds} />}
            <Row label="Replay protection" observation={sa.replay_protection} />
          </tbody>
        </table></div>
        <p className="note" style={{ marginTop: 12 }}>
          Cleartext negotiation only shows the IKE SA. ESP child SA transforms, PFS and IKEv2 authentication travel inside encrypted
          IKE messages, so they are reported as not observable rather than guessed.
        </p>
      </Panel>

      <div className="grid cols-2">
        <Panel title="SA proposals">
          {proposals.selected.length + proposals.offered.length === 0 ? <div className="empty">No cleartext SA proposal captured.</div> : (
            <table className="data">
              <thead><tr><th>Role</th><th>Protocol</th><th>Encryption</th><th>Integrity / PRF</th><th>DH</th></tr></thead>
              <tbody>
                {(["selected", "offered"] as const).flatMap((role) => proposals[role].map((p, i) => (
                  <tr key={`${role}-${i}`}>
                    <td><span className={`badge ${role === "selected" ? "src-observed" : "src-unavailable"}`}>{role}</span></td>
                    <td>{p.protocol}</td>
                    <td className="mono id">{display(p.encryption)}</td>
                    <td className="mono">{display([...(p.integrity ?? []), ...(p.prf ?? [])])}</td>
                    <td className="mono id">{display(p.dh)}</td>
                  </tr>
                )))}
              </tbody>
            </table>
          )}
        </Panel>
        <Panel title="Packet statistics">
          <div className="kv">
            <div>Total packets</div><div>{stats.packet_count?.toLocaleString()}</div>
            <div>IKE messages</div><div>{stats.ike_message_count}</div>
            <div>ESP packets</div><div>{stats.esp_packet_count?.toLocaleString()}</div>
            <div>UDP-encapsulated ESP</div><div>{stats.udp_encapsulated_esp_count}</div>
            <div>AH packets</div><div>{stats.ah_packet_count}</div>
            <div>Replay indicators</div>
            <div>{Object.entries(result.features.replay_indicators).map(([k, v]) => `${k.replaceAll("_", " ")}: ${v}`).join(" · ")}</div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
