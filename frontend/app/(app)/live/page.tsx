"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ErrorBox, Loading, PageHead, Panel, SeverityBadge, bytes, display } from "@/components/ui";
import { api } from "@/lib/api";
import type { LiveSession, LiveStatus } from "@/types";

type Iface = { index: number; name: string; description: string };

export default function LivePage() {
  const router = useRouter();
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [interfaces, setInterfaces] = useState<Iface[] | null>(null);
  const [iface, setIface] = useState("");
  const [seconds, setSeconds] = useState(60);
  const [filter, setFilter] = useState<"ipsec" | "all">("ipsec");
  const [session, setSession] = useState<LiveSession | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.liveStatus().then((s) => { setStatus(s); if (s.active) setSession(s.active); }).catch((e) => setError(e.message));
    api.liveInterfaces().then((list) => {
      setInterfaces(list);
      setIface((list.find((i) => /wi-?fi|ethernet|vethernet/i.test(i.description)) ?? list[0])?.name ?? "");
    }).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!session || !["capturing", "analysing"].includes(session.status)) return;
    const timer = setTimeout(() => api.liveSession(session.id).then(setSession).catch((e) => setError(e.message)), 2000);
    return () => clearTimeout(timer);
  }, [session]);

  async function start() {
    setError(null);
    try {
      setSession(await api.liveStart({ interface: iface, duration_seconds: seconds, filter }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start the capture.");
    }
  }

  const running = session && ["capturing", "analysing"].includes(session.status);
  const snap = session?.snapshot ?? {};
  const progress = session ? Math.min(1, session.elapsed_seconds / session.duration_seconds) : 0;

  return (
    <>
      <PageHead eyebrow="Live network stream" title="Live capture"
        lede="Capture from a network interface of the analyzer host, watch IPsec evidence as it arrives, then get the full analysis automatically." />
      <ErrorBox message={error} />
      {status && !status.available && <div className="error-box">dumpcap was not found on the server; install Wireshark or set DUMPCAP_PATH.</div>}
      <div className="grid cols-3" style={{ marginTop: 12 }}>
        <Panel title="1 · Capture settings">
          {!interfaces ? <Loading label="Listing interfaces" /> : (
            <div className="grid" style={{ gap: 12 }}>
              <div className="field">
                <label htmlFor="iface">Interface</label>
                <select id="iface" className="input" value={iface} disabled={!!running} onChange={(e) => setIface(e.target.value)}>
                  {interfaces.map((i) => <option key={i.name} value={i.name}>{i.index}. {i.description}</option>)}
                </select>
              </div>
              <div className="field">
                <label htmlFor="secs">Duration: {seconds} s</label>
                <input id="secs" type="range" min={10} max={status?.max_seconds ?? 300} step={5} value={seconds} disabled={!!running}
                  onChange={(e) => setSeconds(Number(e.target.value))} />
              </div>
              <div className="field">
                <label>Traffic</label>
                <div className="row">
                  {(["ipsec", "all"] as const).map((f) => (
                    <label key={f} className="row" style={{ gap: 6, fontSize: 14 }}>
                      <input type="radio" name="filter" checked={filter === f} disabled={!!running} onChange={() => setFilter(f)} />
                      {f === "ipsec" ? "IPsec only (IKE, NAT-T, ESP, AH)" : "All traffic"}
                    </label>
                  ))}
                </div>
              </div>
              <div className="row">
                <button className="btn" disabled={!!running || !iface || status?.available === false} onClick={start}>Start capture</button>
                {session?.status === "capturing" && <button className="btn danger" onClick={() => api.liveStop(session.id).then(setSession)}>Stop now</button>}
              </div>
              <p className="note">Admin-only and audited. Limits: {status?.max_seconds ?? "…"} s and {status?.max_megabytes ?? "…"} MB per capture, one capture at a time.
                Captured traffic is stored like an uploaded PCAP and is never decrypted.</p>
            </div>
          )}
        </Panel>

        <Panel title="2 · Live view" className="span-2" aside={session && <span>{session.status}</span>}>
          {!session ? <div className="empty">Start a capture to see IPsec evidence as it arrives.</div> : (
            <div className="grid" style={{ gap: 14 }}>
              <div>
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <span className="mono">{session.interface} · {session.filter === "ipsec" ? "IPsec only" : "all traffic"}</span>
                  <span className="mono muted">{session.elapsed_seconds.toFixed(0)} / {session.duration_seconds} s · {bytes(session.bytes_captured)}</span>
                </div>
                <div className="progress" style={{ marginTop: 8 }}><div style={{ width: `${progress * 100}%` }} /></div>
              </div>
              <div className="grid cols-4">
                <div className="panel stat"><span className="eyebrow" style={{ color: "var(--muted)" }}>Packets</span><strong>{snap.packets ?? "…"}</strong></div>
                <div className="panel stat"><span className="eyebrow" style={{ color: "var(--muted)" }}>IPsec</span><strong>{snap.ipsec_detected === undefined ? "…" : snap.ipsec_detected ? "Detected" : "None yet"}</strong></div>
                <div className="panel stat"><span className="eyebrow" style={{ color: "var(--muted)" }}>ESP packets</span><strong>{snap.esp_packets ?? "…"}</strong><span>{snap.packets_per_second ?? 0} pkt/s</span></div>
                <div className="panel stat"><span className="eyebrow" style={{ color: "var(--muted)" }}>Score so far</span><strong>{snap.security_score ?? "…"}</strong>{snap.risk_level && <SeverityBadge level={snap.risk_level} />}</div>
              </div>
              <div className="kv">
                <div>IKE version</div><div>{display(snap.ike_version)}</div>
                <div>Encryption / DH</div><div>{display(snap.encryption)} · {display(snap.dh_group)}</div>
                <div>IKE messages</div><div>{snap.ike_messages ?? "…"}</div>
                <div>SPIs</div><div className="mono">{display(snap.spis)}</div>
                <div>Protocols</div><div>{display(snap.protocols)}</div>
                <div>Last update</div><div className="muted">{snap.updated_at ? new Date(snap.updated_at).toLocaleTimeString() : "waiting for first packets"}</div>
              </div>
              {snap.paused && <div className="note">{snap.paused}</div>}
              {session.error && <ErrorBox message={session.error} />}
              {session.status === "analysing" && <Loading label="Capture finished; queuing the full analysis" />}
              {session.status === "completed" && session.analysis_id && (
                <div className="row">
                  <span>Capture handed to the analyzer.</span>
                  <button className="btn" onClick={() => router.push(`/analyses/${session.analysis_id}`)}>Open full analysis</button>
                </div>
              )}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
