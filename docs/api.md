# API reference

Base URL: `http://localhost:8001` in local development (Docker: `http://localhost:8000`). Interactive OpenAPI docs are at `/docs` and the schema at `/openapi.json`.

Every endpoint except `/health` and `/api/auth/login` needs `Authorization: Bearer <token>`. Errors are `{"detail": "..."}`, and server errors return a generic 500 with no stack trace.

## Roles

| Role | Can |
|---|---|
| `viewer` | Read every analysis, generate and download reports |
| `analyst` | Upload captures; read, report on and delete **their own** analyses |
| `admin` | Everything, plus users, audit log and (by default) live capture |

An analysis you are not allowed to see returns **404**, not 403, so IDs cannot be probed.

## Authentication

### `POST /api/auth/login`

```json
{"email": "admin@ipsec.local", "password": "..."}
```

→ `200 {"access_token": "...", "expires_at": "2026-09-26T20:00:00+00:00", "user": {...}}`. After `LOGIN_MAX_FAILURES` (5) failures in `LOGIN_LOCKOUT_MINUTES` (15), the account returns 429 until the window passes.

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/auth/me` | any | Current user |
| GET | `/api/auth/users` | admin | List users |
| POST | `/api/auth/users` | admin | `{"email","full_name","password","role"}`. Password: 12+ characters from 3 character classes (422 otherwise); 409 if the email exists |
| PATCH | `/api/auth/users/{id}` | admin | Change `role`, `is_active` or `password`. Admins cannot demote or deactivate themselves |

## Captures and analyses

### `POST /api/captures/upload`

Multipart field `file`. Accepted: `.pcap`, `.pcapng`, `.cap`, with a libpcap or pcapng signature, up to `MAX_UPLOAD_SIZE_BYTES` (100 MB). → `202 {"analysis_id", "capture_id", "filename", "sha256", "size_bytes", "status": "queued"}`.

| Status | Reason |
|---|---|
| 400 | Wrong extension, not a capture (signature check) or empty |
| 413 | Over the size limit |
| 403 | Viewer role |

```bat
curl -H "Authorization: Bearer %TOKEN%" -F "file=@capture_002.pcap" http://localhost:8001/api/captures/upload
```

| Method | Path | Notes |
|---|---|---|
| GET | `/api/analyses?risk=High&status=completed&limit=50&offset=0` | `{"items", "total", "limit", "offset"}`, newest first |
| GET | `/api/analyses/{id}` | Full detail: `capture`, `warnings`, `reports` and `result` (below) |
| GET | `/api/analyses/{id}/status` | `{"analysis_id", "status": "queued\|running\|completed\|failed", "error", "started_at", "completed_at"}` for polling |
| DELETE | `/api/analyses/{id}` | Owner or admin. Removes the analysis, its reports and (if unused) the stored capture |
| GET | `/api/dashboard/summary` | Counts, risk and severity distribution, traffic categories, top findings, compliance overview, average score and AI confidence, recent analyses |

### The `result` document

```text
result
├── packet_count, detected_protocols, tshark_version, warnings
├── features
│   ├── detection        ipsec/ike/esp/ah detected, confidence, evidence
│   ├── protocol         ipsec_protocol, ike_version, ike_exchange_types, ip_version     (Observations)
│   ├── mode             Observation + confidence
│   ├── cryptography     encryption, integrity, prf, authentication, dh_group, pfs       (Observations, IKE SA scope)
│   ├── sa               lifetime, spi_values, replay_protection, payload_confidentiality, nat_traversal,
│   │                    child_rekey_interval_seconds, ike_rekey_interval_seconds
│   ├── ike_proposals    selected[], offered[]
│   ├── rekeys           child/IKE rekey events, PFS evidence
│   ├── replay_indicators, packet_statistics
│   ├── traffic          features{59}, size_histogram, timeline
│   └── esp_structure    features{18}, cipher{status, family, posterior, layout}, summary
├── protocol_inference   esp_cipher{label, confidence, method, probabilities}, mode{...}, evidence, caveat
├── traffic_prediction   label, confidence, probabilities, model{name, version, training_source, cv_accuracy}
├── security             assessment{security_score, risk_level, counts, methodology}, findings[]
├── compliance           {profile_id: evaluation}   (see below)
└── ai_confidence        score, components[{name, value, basis, explanation}], method
```

An `Observation` is `{"value": ..., "source": "observed|observed-majority|inferred|predicted|unavailable", "evidence": [...]}`.

## Compliance

| Method | Path | Notes |
|---|---|---|
| GET | `/api/compliance/profiles` | `[{"id","name","version","reference","description","controls"}]` |
| GET | `/api/analyses/{id}/compliance?profile=nist-sp-800-77r1` | Re-evaluates the stored result against the profile now. 409 until the analysis completes, 404 for an unknown profile |

The evaluation has the shape:

```json
{
  "profile": {"id": "nist-sp-800-77r1", "name": "...", "version": "...", "reference": "...", "disclaimer": "..."},
  "verdict": "compliant | non-compliant | insufficient evidence",
  "counts": {"pass": 7, "fail": 1, "unknown": 3, "not_applicable": 1},
  "pass_rate": 0.875,
  "failed_by_severity": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0},
  "controls": [{"id": "NIST-05", "title": "...", "status": "fail", "basis": "observed", "observed": "DH2 (MODP-1024)",
                "evidence": "...", "reference": "...", "remediation": "...", "severity": "High"}]
}
```

## Reports

| Method | Path | Notes |
|---|---|---|
| GET | `/api/analyses/{id}/narrative?llm=true` | `{"narrative": {executive_summary, technical_explanation, remediation[], limitations[]}, "source", "llm_available", "facts"}`. `llm` defaults to false |
| POST | `/api/analyses/{id}/reports` | `{"kind": "executive" \| "technical"}` → `201 {"id", "kind", "size_bytes", "narrative_source", "created_at"}`. Reports and narratives return 409 until the analysis completes |
| GET | `/api/reports/{id}/download` | `application/pdf`; 410 if the file was removed from storage |
| GET | `/api/audit?limit=100` | Admin. Audit entries, newest first |

If the LLM is disabled, unavailable, or its text fails the grounding check (it names a value that is not in the facts), the deterministic narrative is used and `source` says so.

## Live capture

Allowed roles: `LIVE_CAPTURE_ROLES` (default `admin`); other roles get 403.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/live/status` | `{"available", "max_seconds", "max_megabytes", "filters": ["ipsec","all"], "active"}` |
| GET | `/api/live/interfaces` | Interfaces reported by `dumpcap -D`; 503 if dumpcap is missing |
| POST | `/api/live/sessions` | `{"interface": "<exact name from /interfaces>", "duration_seconds": 5-3600, "filter": "ipsec" \| "all"}` → 201. 409 if a capture is already running |
| GET | `/api/live/sessions/{id}` | Status, elapsed time, bytes, rolling `snapshot`, and `analysis_id` when finished |
| POST | `/api/live/sessions/{id}/stop` | Stop early; the capture so far is analysed |

## Health

`GET /health` (public):

```json
{"status": "ok", "service": "IPsec Analyzer",
 "tshark": {"available": true, "version": "TShark (Wireshark) 4.6.0 ...", "field_check": "ok", "missing_fields": [], "missing_preferences": []}}
```

If `missing_fields` is not empty, the installed Wireshark lacks dissector fields the parser needs; upgrade Wireshark.
