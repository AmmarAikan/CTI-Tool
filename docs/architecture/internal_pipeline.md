# Internal Runtime Pipeline

Two internal runtime paths are implemented: Wazuh `alerts.json` and the official Dionaea `log_json` output. Both accept JSON arrays, wrapper objects, JSONL, and NDJSON.

Supported first source:

```text
Wazuh alerts.json
Dionaea honeypot JSON logs
```

Future connector extensions can include:

```text
IDS/IPS
Suricata
Zeek
Sysmon
firewall logs
server logs
application logs
```

Implemented processing flow:

```text
Internal Connector
-> Raw Log Storage
-> Log Parsing
-> Normalization
-> Structured Field Extraction
-> IoC and IoA Extraction
-> Session Building
-> Outlier / Anomaly Detection
-> Internal CTI Objects
-> PostgreSQL CTI Repository
```

Structured security logs should not be forced through the external document classifier. Classification is only appropriate for internal records that contain significant unstructured natural-language text, such as analyst notes or incident reports.

## Wazuh normalization

The connector extracts a stable record identifier, timestamp, rule description, full log text, source IP, destination fields, rule level, URL, and ports while preserving the complete original alert in `raw_data`. Every raw alert is stored before session analysis.

## Dionaea normalization

The Dionaea connector reads the JSONL emitted by the official `log_json` incident handler. It extracts timestamps, connection type, protocol, transport, source/destination addresses and ports, and credential/command counts. Attempted password values are never copied into the CTI description. The original record is retained in protected raw storage, while the CTI event copy redacts password, token, secret, API-key, and authorization fields.

## Session building

Records are grouped by source type and source IP. A new session starts when the same source remains idle for more than 30 minutes, following the paper's session concept. Alerts without a source IP are grouped by a stable agent/record fallback so they are retained rather than dropped.

## Features and outlier detection

The feature vector includes:

```text
alert count
duration in minutes
maximum and average Wazuh rule level
distinct rules
unique destinations, URLs, and ports
CVE, IP, and domain counts
failed actions
credential attempts
HTTP GET and POST counts
```

Four or more sessions use a deterministic Isolation Forest (`random_state=42`). Smaller files use a transparent rule-based fallback because training Isolation Forest on one to three sessions would create misleading results. The stored `detector_backend` field makes this distinction explicit.

Outlier sessions become internal CTI events. Inlier sessions remain available in the `outlier_sessions` table for baseline and investigation. No automatic model retraining is performed.

## Implementation files

```text
backend/app/pipeline/ingestion/internal/base_internal_connector.py
backend/app/pipeline/ingestion/internal/wazuh_connector.py
backend/app/pipeline/ingestion/internal/dionaea_connector.py
backend/app/pipeline/ingestion/internal/json_file_reader.py
backend/app/pipeline/outlier/sessionizer.py
backend/app/pipeline/outlier/feature_extractor.py
backend/app/pipeline/outlier/detector.py
backend/app/pipeline/internal_orchestrator.py
```

The reproducible local honeypot definition is under `infra/dionaea/`. The safe local lab publishes no host ports and is started explicitly with the Compose `honeypot` profile.
