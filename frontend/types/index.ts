export type Role = "admin" | "analyst" | "viewer";
export type Status = "queued" | "running" | "completed" | "failed";
export type Severity = "Critical" | "High" | "Medium" | "Low";
export type Source = "observed" | "observed-majority" | "inferred" | "predicted" | "unavailable";

export type User = {
  id: string;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
  created_at?: string;
  last_login_at?: string | null;
};

export type TokenResponse = { access_token: string; expires_at: string; user: User };

export type Observation<T = unknown> = { value: T; source: Source; evidence: string[] };

export type AnalysisSummary = {
  analysis_id: string;
  filename: string;
  status: Status;
  packet_count: number;
  detected_protocols: string[];
  ipsec_detected: boolean | null;
  security_score: number | null;
  risk_level: Severity | null;
  predicted_traffic: string | null;
  ike_version: string | null;
  error: string | null;
  created_at: string | null;
  completed_at: string | null;
  owner: string | null;
};

export type Finding = {
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  condition: string;
  evidence: string;
  impact: string;
  recommendation: string;
  source: Source;
};

export type Assessment = {
  security_score: number;
  score_name: string;
  risk_level: Severity;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  methodology: { baseline: number; penalties: Record<Severity, number>; formula: string; thresholds: Record<string, string>; disclaimer: string };
};

export type Proposal = { ike_version: string; protocol: string; encryption?: string[]; integrity?: string[]; prf?: string[]; dh?: string[] };

export type TrafficMetadata = {
  source: string;
  scope: string;
  direction_basis: string;
  features: Record<string, number>;
  size_histogram: { range: string; packets: number }[];
  timeline: { t: number; packets: number; bytes_up: number; bytes_down: number }[];
};

export type Prediction = {
  status: "predicted" | "unavailable";
  source: Source;
  label: string | null;
  confidence: number | null;
  confidence_note?: string;
  probabilities?: Record<string, number>;
  model?: {
    name: string;
    version: string;
    training_source: string;
    trained_at: string;
    test_metrics: { accuracy?: number; macro_f1?: number; samples?: number };
    cv_accuracy?: number | null;
    cv_accuracy_by_source?: Record<string, number>;
  };
  reason?: string;
  caveat: string;
};

export type Features = {
  detection: { ipsec_detected: boolean; ike_detected: boolean; esp_detected: boolean; ah_detected: boolean; ike_version: string; confidence: number; confidence_method: string; evidence: string[] };
  protocol: { ipsec_protocol: string; ike_version: Observation<string>; ike_exchange_types: Observation<string[] | string>; ip_version: Observation<string> };
  mode: Observation<string> & { confidence: number };
  cryptography: {
    scope: string;
    encryption_algorithm: Observation;
    integrity_algorithm: Observation;
    prf_algorithm: Observation;
    authentication_method: Observation;
    dh_group: Observation;
    pfs: Observation;
  };
  sa: {
    sa_lifetime_seconds: Observation;
    ike_rekey_interval_seconds?: Observation;
    child_rekey_interval_seconds?: Observation;
    spi_values: Observation<string[] | string>;
    replay_protection: Observation;
    payload_confidentiality: Observation;
    nat_traversal: Observation;
  };
  replay_indicators: Record<string, number>;
  ike_proposals: { selected: Proposal[]; offered: Proposal[] };
  traffic: TrafficMetadata;
  packet_statistics: Record<string, number>;
};

export type InferredValue = {
  label: string | null;
  confidence: number | null;
  method: string;
  probabilities?: Record<string, number>;
  reason?: string;
  cv_accuracy?: number | null;
  key_length?: string;
  layout?: { iv_bytes: number; padding_block: number; icv_bytes: number };
};

export type ProtocolInference = {
  status: "predicted" | "unavailable";
  reason?: string;
  model_version?: string | null;
  esp_cipher?: InferredValue;
  mode?: InferredValue;
  evidence?: string[];
  caveat: string;
};

export type AnalysisResult = {
  packet_count: number;
  detected_protocols: string[];
  tshark_version?: string;
  warnings?: string[];
  features: Features;
  security: { assessment: Assessment; findings: Finding[] };
  traffic_prediction?: Prediction;
  protocol_inference?: ProtocolInference;
  ai_confidence?: AiConfidence;
};

export type AiConfidence = {
  score: number | null;
  components: { name: string; value: number; basis: string; explanation: string }[];
  method: string;
};

export type ReportInfo = { id: string; kind: "executive" | "technical"; size_bytes: number; narrative_source: string; created_at: string | null };

export type AnalysisDetail = AnalysisSummary & {
  capture: { id: string; filename: string; sha256: string; size_bytes: number; file_format: string; uploaded_at: string | null };
  warnings: string[];
  result: AnalysisResult | Record<string, never>;
  reports: ReportInfo[];
};

export type DashboardSummary = {
  total_analyses: number;
  completed_analyses: number;
  failed_analyses: number;
  pending_analyses: number;
  ipsec_detections: number;
  high_risk_captures: number;
  critical_findings: number;
  findings_by_severity: Record<Severity, number>;
  risk_distribution: Record<Severity, number>;
  traffic_categories: Record<string, number>;
  top_findings: { rule_id: string; title: string; count: number }[];
  ike_versions: Record<string, number>;
  average_score: number | null;
  average_ai_confidence?: number | null;
  compliance?: { profile: string; profile_name: string; verdicts: Record<string, number>; top_failed_controls: { id: string; title: string; count: number }[] };
  recent: AnalysisSummary[];
};

export type Narrative = {
  narrative: { executive_summary: string; technical_explanation: string; remediation: string[]; limitations: string[] };
  source: string;
  llm_available: boolean;
};

export type ComplianceControl = {
  id: string;
  title: string;
  requirement: string;
  severity: Severity;
  status: "pass" | "fail" | "unknown" | "not_applicable";
  basis: Source | null;
  observed: unknown;
  evidence: string;
  reference: string;
  remediation: string;
};

export type ComplianceEvaluation = {
  profile: { id: string; name: string; version: string; reference: string; description: string; disclaimer: string };
  verdict: "compliant" | "non-compliant" | "insufficient evidence";
  counts: { pass: number; fail: number; unknown: number; not_applicable: number };
  pass_rate: number | null;
  failed_by_severity: Record<Severity, number>;
  controls: ComplianceControl[];
};

export type LiveSnapshot = {
  updated_at?: string;
  packets?: number;
  protocols?: string[];
  ipsec_detected?: boolean;
  ike_version?: string;
  esp_packets?: number;
  ike_messages?: number;
  spis?: string[] | string;
  packets_per_second?: number;
  encryption?: string;
  dh_group?: string;
  security_score?: number;
  risk_level?: Severity;
  findings?: number;
  paused?: string;
  error?: string;
};

export type LiveSession = {
  id: string;
  status: "capturing" | "analysing" | "completed" | "failed";
  interface: string;
  filter: "ipsec" | "all";
  duration_seconds: number;
  elapsed_seconds: number;
  started_at: string;
  bytes_captured: number;
  snapshot: LiveSnapshot;
  analysis_id: string | null;
  error: string | null;
  owner: string;
};

export type LiveStatus = { available: boolean; max_seconds: number; max_megabytes: number; filters: string[]; active: LiveSession | null };

export type AuditEntry = {
  id: string;
  user_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  ip_address: string | null;
  outcome: string;
  detail: Record<string, unknown>;
  created_at: string | null;
};
