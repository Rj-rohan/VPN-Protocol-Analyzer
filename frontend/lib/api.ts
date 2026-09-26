import type {
  AnalysisDetail, AnalysisSummary, AuditEntry, ComplianceEvaluation, DashboardSummary, LiveSession, LiveStatus, Narrative, ReportInfo, Role, TokenResponse, User,
} from "@/types";

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TOKEN_KEY = "ipsec.session";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// Session tokens live in sessionStorage: cleared when the tab closes, never shared across tabs.
export const session = {
  get(): { token: string; user: User; expires_at: string } | null {
    try {
      const raw = sessionStorage.getItem(TOKEN_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return new Date(parsed.expires_at) > new Date() ? parsed : null;
    } catch {
      return null;
    }
  },
  set(value: TokenResponse) {
    try {
      sessionStorage.setItem(TOKEN_KEY, JSON.stringify({ token: value.access_token, user: value.user, expires_at: value.expires_at }));
    } catch {
      /* storage unavailable: the session lasts for this page only */
    }
  },
  clear() {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* ignore */
    }
  },
};

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = session.get()?.token;
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the analyzer API. Check that the backend is running.");
  }
  if (response.status === 401 && path !== "/api/auth/login") {
    session.clear();
    window.dispatchEvent(new Event("ipsec:logout"));
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail)) message = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return response.headers.get("content-type")?.includes("application/json") ? response.json() : (response.blob() as Promise<T>);
}

export const api = {
  login: (email: string, password: string) => request<TokenResponse>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  me: () => request<User>("/api/auth/me"),
  dashboard: () => request<DashboardSummary>("/api/dashboard/summary"),
  analyses: (params: { limit?: number; offset?: number; risk?: string; status?: string } = {}) => {
    const query = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)]));
    return request<{ items: AnalysisSummary[]; total: number; limit: number; offset: number }>(`/api/analyses?${query}`);
  },
  analysis: (id: string) => request<AnalysisDetail>(`/api/analyses/${id}`),
  status: (id: string) => request<{ status: string; error: string | null }>(`/api/analyses/${id}/status`),
  deleteAnalysis: (id: string) => request<void>(`/api/analyses/${id}`, { method: "DELETE" }),
  narrative: (id: string, llm: boolean) => request<Narrative>(`/api/analyses/${id}/narrative?llm=${llm}`),
  createReport: (id: string, kind: "executive" | "technical") =>
    request<ReportInfo>(`/api/analyses/${id}/reports`, { method: "POST", body: JSON.stringify({ kind }) }),
  downloadReport: async (report: ReportInfo, analysisId: string) => {
    const blob = await request<Blob>(`/api/reports/${report.id}/download`);
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement("a"), { href: url, download: `ipsec-${report.kind}-report-${analysisId.slice(0, 8)}.pdf` });
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
  users: () => request<User[]>("/api/auth/users"),
  createUser: (body: { email: string; full_name: string; password: string; role: Role }) =>
    request<User>("/api/auth/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id: string, body: { role?: Role; is_active?: boolean }) =>
    request<User>(`/api/auth/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  audit: (limit = 100) => request<AuditEntry[]>(`/api/audit?limit=${limit}`),
  compliance: (id: string) => request<{ default: string; evaluations: Record<string, ComplianceEvaluation> }>(`/api/analyses/${id}/compliance`),
  liveStatus: () => request<LiveStatus>("/api/live/status"),
  liveInterfaces: () => request<{ index: number; name: string; description: string }[]>("/api/live/interfaces"),
  liveStart: (body: { interface: string; duration_seconds: number; filter: "ipsec" | "all" }) =>
    request<LiveSession>("/api/live/sessions", { method: "POST", body: JSON.stringify(body) }),
  liveSession: (id: string) => request<LiveSession>(`/api/live/sessions/${id}`),
  liveStop: (id: string) => request<LiveSession>(`/api/live/sessions/${id}/stop`, { method: "POST" }),
  health: () => request<{ status: string; tshark: { available: boolean; version?: string; error?: string } }>("/health"),
};

/** Upload with progress events (fetch cannot report upload progress). */
export function uploadCapture(file: File, onProgress: (fraction: number) => void): Promise<{ analysis_id: string; status: string }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_URL}/api/captures/upload`);
    const token = session.get()?.token;
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.upload.onprogress = (event) => event.lengthComputable && onProgress(event.loaded / event.total);
    xhr.onerror = () => reject(new ApiError(0, "Upload failed: cannot reach the analyzer API."));
    xhr.onload = () => {
      let body: { detail?: string; analysis_id?: string; status?: string } = {};
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        /* ignore */
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body as { analysis_id: string; status: string });
      else {
        if (xhr.status === 401) {
          session.clear();
          window.dispatchEvent(new Event("ipsec:logout"));
        }
        reject(new ApiError(xhr.status, typeof body.detail === "string" ? body.detail : `Upload failed (${xhr.status})`));
      }
    };
    const form = new FormData();
    form.append("file", file);
    xhr.send(form);
  });
}
