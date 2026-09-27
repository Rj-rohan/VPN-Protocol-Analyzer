import type { ReactNode } from "react";
import type { Severity, Source, Status } from "@/types";

export const SEVERITY_COLORS: Record<Severity, string> = { Critical: "#b3261e", High: "#d9480f", Medium: "#a67c00", Low: "#2f6f4f" };
export const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

export function SeverityBadge({ level }: { level: Severity | null | undefined }) {
  if (!level) return <span className="badge src-unavailable">n/a</span>;
  return <span className={`badge sev-${level}`}>{level}</span>;
}

const SOURCE_LABELS: Record<Source, string> = {
  observed: "observed", "observed-majority": "observed (majority)", inferred: "inferred", predicted: "predicted", unavailable: "not observable",
};

export function SourceBadge({ source }: { source: Source | undefined }) {
  const value = source ?? "unavailable";
  return <span className={`badge src-${value}`} title="Where this value comes from">{SOURCE_LABELS[value] ?? value}</span>;
}

export function StatusBadge({ status }: { status: Status }) {
  return <span className={`badge st-${status}`}>{status}</span>;
}

export function Panel({ title, aside, children, className = "" }: { title?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {title && <h2 className="panel-title"><span>{title}</span>{aside}</h2>}
      {children}
    </section>
  );
}

export function Stat({ label, value, alert = false }: { label: string; value: ReactNode; alert?: boolean }) {
  return (
    <div className={`panel stat ${alert ? "alert" : ""}`}>
      <span className="eyebrow" style={{ color: "var(--muted)" }}>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function PageHead({ eyebrow, title, lede, actions }: { eyebrow: string; title: string; lede?: string; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        {lede && <p className="lede">{lede}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </header>
  );
}

export function ErrorBox({ message }: { message: string | null }) {
  return message ? <div className="error-box" role="alert">{message}</div> : null;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return <div className="empty"><span className="mono">{label}…</span></div>;
}

export function display(value: unknown): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "—";
  return String(value);
}

export function when(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 ** 2).toFixed(2)} MB`;
}
