"use client";

import { useRouter } from "next/navigation";
import { DragEvent, useRef, useState } from "react";
import { ErrorBox, PageHead, Panel, bytes } from "@/components/ui";
import { api, uploadCapture } from "@/lib/api";

const ALLOWED = [".pcap", ".pcapng", ".cap"];
const MAX_BYTES = 100 * 1024 * 1024;
const STEPS = ["Upload", "Queued", "TShark parsing & rule engine", "Complete"];

function validate(file: File): string | null {
  const name = file.name.toLowerCase();
  if (!ALLOWED.some((ext) => name.endsWith(ext))) return `Only ${ALLOWED.join(", ")} files are accepted.`;
  if (file.size === 0) return "The file is empty.";
  if (file.size > MAX_BYTES) return `The file is ${bytes(file.size)}; the limit is ${bytes(MAX_BYTES)}.`;
  return null;
}

export default function UploadPage() {
  const router = useRouter();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [progress, setProgress] = useState(0);
  const [step, setStep] = useState(-1);
  const [error, setError] = useState<string | null>(null);

  const busy = step >= 0 && step < 3;

  async function start(chosen: File) {
    const problem = validate(chosen);
    setFile(chosen);
    setError(problem);
    if (problem) return;
    try {
      setStep(0);
      setProgress(0);
      const created = await uploadCapture(chosen, setProgress);
      setStep(1);
      for (let attempt = 0; attempt < 600; attempt++) {
        const status = await api.status(created.analysis_id);
        if (status.status === "running") setStep(2);
        if (status.status === "completed") {
          setStep(3);
          router.push(`/analyses/${created.analysis_id}`);
          return;
        }
        if (status.status === "failed") throw new Error(status.error ?? "Analysis failed.");
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      throw new Error("Analysis is taking unusually long; check the Analyses page later.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed.");
      setStep(-1);
    }
  }

  function onDrop(event: DragEvent) {
    event.preventDefault();
    setOver(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped && !busy) start(dropped);
  }

  return (
    <>
      <PageHead eyebrow="Capture intake" title="Upload PCAP" lede="Upload an authorized IPsec capture. It is stored in controlled storage, never decrypted, and analyzed in the background." />
      <div className="grid cols-2">
        <Panel title="1 · Select capture">
          <div
            className={`dropzone ${over ? "over" : ""} ${busy ? "busy" : ""}`}
            onClick={() => !busy && input.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setOver(true); }}
            onDragLeave={() => setOver(false)}
            onDrop={onDrop}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && !busy && input.current?.click()}
          >
            <span style={{ fontSize: 40, lineHeight: 1 }}>↑</span>
            <strong>{busy ? "Analyzing…" : "Drop a capture here"}</strong>
            <small>or click to browse · .pcap, .pcapng, .cap · up to 100 MB</small>
            <input ref={input} type="file" accept={ALLOWED.join(",")} hidden onChange={(e) => e.target.files?.[0] && start(e.target.files[0])} />
          </div>
          {file && <p className="mono muted" style={{ marginTop: 12 }}>{file.name} · {bytes(file.size)}</p>}
          <ErrorBox message={error} />
        </Panel>
        <Panel title="2 · Analysis progress">
          <div className="steps">
            {STEPS.map((label, index) => (
              <div key={label} className={`step ${step > index || step === 3 ? "done" : step === index ? "active" : ""}`}>
                <i />{label}{index === 0 && step === 0 && <span className="mono muted">{Math.round(progress * 100)}%</span>}
              </div>
            ))}
          </div>
          {step === 0 && <div className="progress" style={{ marginTop: 16 }}><div style={{ width: `${progress * 100}%` }} /></div>}
          <div className="note" style={{ marginTop: 18 }}>
            The server checks the file signature, stores it under its SHA-256 hash, runs TShark without a shell, extracts IKE/ESP/AH evidence,
            applies the security rules and predicts a traffic category. Values that are not visible on the wire are reported as
            &ldquo;Unknown / Not observable&rdquo;, never guessed.
          </div>
        </Panel>
      </div>
    </>
  );
}
