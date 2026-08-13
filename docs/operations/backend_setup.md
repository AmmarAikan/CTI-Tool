# Backend Setup and Operations

## Recommended development path

1. Start Docker Desktop.
2. Copy `.env.example` to `.env`.
3. Replace every `CHANGE_ME` value with a strong local secret.
4. Run `docker compose up --build`.
5. Open `http://localhost:8000/docs`.
6. Log in through `POST /api/v1/auth/login` with the bootstrap administrator from `.env`.

The Compose stack starts PostgreSQL and the backend. PostgreSQL health must pass before the backend starts. The database is reachable only inside the Compose network and has no Windows host port; the API is bound to `127.0.0.1:8000`. Database data and uploads are kept in named Docker volumes.

## PostgreSQL browser with Adminer

Adminer is an optional, local-only database browser. Start it without restarting or exposing PostgreSQL:

```powershell
docker compose --profile database-ui up -d adminer
```

Open `http://127.0.0.1:8080` and enter:

```text
System: PostgreSQL
Server: db
Username: the POSTGRES_USER value from .env (normally cti)
Password: the POSTGRES_PASSWORD value from .env
Database: the POSTGRES_DB value from .env (normally cti_platform)
```

The server must be `db`, not `localhost`, because Adminer and PostgreSQL communicate through the Compose network. The PostgreSQL port remains unpublished. Adminer is bound only to the local loopback address and does not receive the database password as a container environment variable.

After login, select a table from the left menu and use **Select data** to inspect rows or **Structure** to inspect columns and constraints. Prefer read-only browsing. Adminer can run SQL and modify or delete data, so do not use destructive actions while demonstrating the project.

Stop only the optional browser with:

```powershell
docker compose stop adminer
```

To start the full local lab and the database browser together:

```powershell
docker compose --profile honeypot --profile database-ui up --build -d
```

## Local SQLite path

SQLite is the default when `DATABASE_URL` is absent. One Python 3.12 environment named `.venv` is shared by the backend, external collectors, and Part 0 model tools:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
```

The default file is `data/cti_platform.db` and is ignored by Git.

## Demonstrating the internal pipeline

1. Authenticate in Swagger using the token from `/auth/login`.
2. Call `POST /uploads/wazuh`.
3. Upload `data/internal_samples/wazuh_alerts_sample.json`.
4. Inspect `/outliers`, `/events`, `/indicators`, `/runs`, and `/dashboard/summary`.
5. Export an event with `/events/{event_id}/stix`.
6. Preview its MISP mapping with `/events/{event_id}/misp` and `dry_run=true`.

## Local isolated Dionaea lab

Dionaea uses the official `dinotools/dionaea:0.11.0` image pinned by digest. The repository enables the official `log_json` incident handler and stores its JSONL output in a named volume shared read-only with the backend.

Start the normal stack plus the honeypot profile:

```powershell
docker compose --profile honeypot up --build
```

No Dionaea port is published to Windows, the LAN, or the internet. The backend and Dionaea share the isolated `honeypot_lab` network, allowing a harmless HTTP interaction to be generated entirely inside Docker:

```powershell
docker compose exec backend python -c "from urllib.request import urlopen; print(urlopen('http://dionaea/').status)"
```

After authentication, call `POST /api/v1/internal/dionaea/collect`. The backend reads `/data/dionaea/dionaea.json`, stores the raw events, creates source-IP sessions, detects outliers, and persists resulting CTI events. Alternatively upload an exported Dionaea JSON/JSONL file through `POST /api/v1/uploads/dionaea`.

For a deterministic demonstration without starting the container, upload `data/internal_samples/dionaea_events_sample.jsonl`. It contains documentation-only addresses and fake credentials.

Do not publish the Dionaea ports on a personal machine. The `honeypot_lab` Docker network is internal, and this local profile is not intended to capture public attacks.

## MISP

MISP is optional and intentionally separate from the core Compose stack because it is a multi-service platform with its own MariaDB, Redis, modules, TLS, updates, and security lifecycle.

Use the official `MISP/misp-docker` project when a real instance is needed. Configure its administrator and TLS, then set these variables in this project's `.env`:

```text
MISP_URL=https://your-misp-instance
MISP_API_KEY=your-automation-key
MISP_VERIFY_TLS=true
```

Verify connectivity through `GET /api/v1/misp/health`. Start with `dry_run=true`. Only an administrator can perform a real send (`dry_run=false`). Events are created unpublished by default.

Do not commit MISP credentials or disable TLS verification outside a disposable local lab.

## Model priority

Runtime NER uses:

1. Primary: `ml/models/dnrti_bert_ner`
2. Secondary fallback: `ml/models/dnrti_sklearn_ner/model.joblib`
3. Safe degradation: no NER entities when neither loads

The Docker image includes the secondary sklearn model. Compose mounts the local primary BERT directory read-only at runtime because its large files are intentionally excluded from Git. If that directory is absent or incomplete, the extractor falls back to sklearn and reports its active backend accordingly. BERT increases runtime memory requirements but no longer inflates the application image.

## Current boundaries

- The API runs work synchronously; Redis/Celery is deferred until job volume requires it.
- Live Wazuh streaming is deferred; the current interface processes real exports and samples.
- MISP is a sharing target, not a hard runtime dependency.
- No automatic NVD enrichment occurs during ingestion, avoiding rate-limit surprises. Analysts trigger it per event.
- No automatic Isolation Forest retraining occurs.

See `docs/architecture/future_bound_work.md` for the full scope and rationale of MongoDB, hosted MISP, live Wazuh, workers, TAXII, and other deferred infrastructure.
