# Deployment

## Option A: Docker Compose (full stack)

Requirements: Docker Desktop, or Docker Engine with Compose v2.

```bat
copy .env.example .env
:: edit .env: POSTGRES_PASSWORD, JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD (and ANTHROPIC_API_KEY if wanted)
docker compose up --build -d
docker compose logs -f backend
```

| Service | URL | Notes |
|---|---|---|
| Frontend | http://localhost:3000 (`FRONTEND_PORT`) | `PUBLIC_API_URL` is compiled into the bundle, so rebuild after changing it |
| Backend | http://localhost:8000 (`BACKEND_PORT`), docs at `/docs` | Runs as non-root user `analyzer`; TShark installed without setuid dumpcap |
| PostgreSQL | internal only | Volume `postgres_data` |

Captures and reports persist in the `pcap_storage` volume. `./data/models` is mounted read-only at `/models`, so retrained models are picked up after `docker compose restart backend`.

**Live capture in Docker** needs the backend on the host network with capture capabilities, and dumpcap installed with capture rights. Add a `docker-compose.override.yml`:

```yaml
services:
  backend:
    network_mode: host
    cap_add: [NET_RAW, NET_ADMIN]
```

This only works on Linux hosts. On Windows, run the backend natively (option B) for live capture.

## Option B: Local services on Windows (no Docker)

Requirements: Python 3.11, Node.js 22, PostgreSQL 16, and Wireshark 4.x (TShark + dumpcap; include Npcap for live capture).

```bat
:: one-time setup
psql -U postgres -c "CREATE ROLE ipsec LOGIN PASSWORD 'ipsec';" -c "CREATE DATABASE ipsec_analyzer OWNER ipsec;"
python -m venv .venv
.venv\Scripts\python -m pip install -r backend\requirements.txt
cd frontend && npm install && cd ..
```

`backend\.env`:

```
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
JWT_SECRET=<python -c "import secrets; print(secrets.token_urlsafe(48))">
ADMIN_EMAIL=admin@ipsec.local
ADMIN_PASSWORD=<12+ characters, 3 character classes>
```

`frontend\.env.local`:

```
NEXT_PUBLIC_API_URL=http://localhost:8001
```

Run each service in its own terminal:

```bat
:: terminal 1: backend (Alembic migrations run on startup)
cd backend
..\.venv\Scripts\python -m uvicorn app.main:app --reload --port 8001

:: terminal 2: frontend
cd frontend
npm run dev
```

Check that the stack works: http://localhost:8001/health should report `"tshark": {"available": true, "field_check": "ok"}`. Then sign in at http://localhost:3000.

For a production-style frontend, use `npm run build && npm start`. Stop `npm run dev` first, because both write to `.next`.

## Configuration reference

All backend settings are environment variables (or `backend/.env`), case-insensitive.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://ipsec:ipsec@localhost:5432/ipsec_analyzer` | SQLAlchemy URL |
| `JWT_SECRET` | random per process | **Set in production**, otherwise tokens stop working on restart |
| `JWT_EXPIRY_MINUTES` | 480 | Token lifetime |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | — | First admin, created when the users table is empty |
| `LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_MINUTES` | 5, 15 | Login throttling |
| `STORAGE_DIR`, `REPORT_DIR` | `./storage/pcaps`, `./storage/reports` | Capture and PDF storage |
| `MAX_UPLOAD_SIZE_BYTES` | 104857600 | Upload limit |
| `ALLOWED_EXTENSIONS` | `.pcap,.pcapng,.cap` | Upload extension allow-list |
| `TSHARK_PATH`, `TSHARK_TIMEOUT_SECONDS` | `tshark`, 120 | TShark binary and per-pass timeout |
| `ANALYSIS_EXECUTION`, `ANALYSIS_WORKERS` | `background`, 2 | Worker mode and threads |
| `DUMPCAP_PATH` | next to TShark | Live capture binary |
| `LIVE_CAPTURE_ROLES` | `admin` | Comma-separated roles allowed to capture |
| `LIVE_CAPTURE_MAX_SECONDS`, `LIVE_CAPTURE_MAX_MEGABYTES` | 300, 100 | Capture limits |
| `LIVE_SNAPSHOT_INTERVAL_SECONDS` | 5 | Rolling re-analysis interval |
| `COMPLIANCE_PROFILE_DIR` | — | Extra compliance profile folder |
| `DEFAULT_COMPLIANCE_PROFILE` | `nist-sp-800-77r1` | Profile for the dashboard and executive report |
| `MODEL_DIR` | `<repo>/data/models` | Model artifacts |
| `ANTHROPIC_API_KEY`, `LLM_MODEL`, `LLM_ENABLED` | —, `claude-opus-5`, true | Optional narrative layer |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated frontend origins |

## Operations

| Task | Command |
|---|---|
| Create a user | `python -m app.cli create-user someone@org --role analyst` (from `backend`) |
| Retrain the traffic model | `python -m app.ml.train --source combined` |
| Retrain protocol inference | `python -m app.ml.protocol_models` |
| Evaluate against the testbed | `python -m app.evaluation` |
| Build the dataset package | `python -m app.dataset_export --zip` |
| Back up | `pg_dump ipsec_analyzer` plus the storage directories |
| Roll back a model | Copy `data/models/versions/<version>/*` into `data/models/` and restart |

## Production checklist

- [ ] `JWT_SECRET`, `POSTGRES_PASSWORD` and `ADMIN_PASSWORD` are long and random
- [ ] TLS terminates in front of both services (reverse proxy); `CORS_ORIGINS` lists only the real frontend origin
- [ ] The storage volumes are backed up, and on encrypted disks (captures are sensitive)
- [ ] Live capture is limited to the roles that need it
- [ ] The audit log is exported to your SIEM (`GET /api/audit`, or the `audit_logs` table)
- [ ] `/health` is monitored; `missing_fields` is empty after Wireshark upgrades
