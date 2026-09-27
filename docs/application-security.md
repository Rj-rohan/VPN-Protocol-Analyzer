# Application security

The analyzer handles sensitive network captures, so it is built to the same standard it checks.

## Threat model

| Asset | Threat | Control |
|---|---|---|
| Uploaded captures | Read by another user | Per-owner isolation; inaccessible analyses return 404 |
| Uploaded captures | Malicious file exploits the parser | Extension allow-list, magic-byte check, size limit; TShark runs as an unprivileged process with an argument list, a timeout and bounded stderr |
| Server filesystem | Path traversal through the filename | Only the final path component is kept, and only `[A-Za-z0-9._-]`; leading dots stripped; stored under a SHA-256 prefix |
| Host | Command injection through live capture | Interface must exactly match a `dumpcap -D` entry; filters are presets only; no shell |
| Accounts | Password guessing | scrypt hashes; 12+ characters from 3 classes; lockout after 5 failures in 15 min (HTTP 429) |
| Sessions | Token forgery | HS256 JWT with `JWT_SECRET`, expiry 8 h; inactive users rejected on every request |
| Reports | Fabricated values in the AI narrative | The LLM receives only the fact sheet; a grounding check rejects any algorithm, group or number not in the facts |
| Error pages | Information leakage | Generic 500 body; no stack traces; `Cache-Control: no-store` on the API |
| Browser | Clickjacking, MIME sniffing | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| Actions | Repudiation | Audit log of logins, uploads (including rejected ones), views, reports, downloads, deletions, user changes and live captures |
| Secrets | Committed to git | Environment only; `.env`, `.env.local` and generated testbed configs are gitignored; the testbed generates a new PSK every run |

## Authorization matrix

| Action | Viewer | Analyst | Admin |
|---|---|---|---|
| Upload | – | ✓ | ✓ |
| View analysis | all | own | all |
| Delete analysis | – | own | all |
| Generate / download reports | all | own | all |
| Live capture | – | – | ✓ (configurable) |
| Manage users | – | – | ✓ |
| Audit log | – | – | ✓ |

Checks are enforced in FastAPI dependencies (`backend/app/core/deps.py`), not in the frontend. The frontend hides links only for convenience.

## Data handling

- **Payloads are never decrypted.** Stored results contain headers, sizes, timings and derived features.
- **Captures are stored whole,** because they are needed to re-run analyses and for audit. Delete an analysis to remove its capture, unless another analysis shares the same file.
- **PDF reports** are marked confidential and name the capture's SHA-256 for chain of custody.

## Testing

`backend/tests/test_auth.py` and `test_api.py` cover role enforcement, cross-user isolation (404), lockout, weak password rejection, upload validation (extension, signature, size, empty file, traversal names) and audit entries.
