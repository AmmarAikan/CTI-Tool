# Internal Runtime Pipeline

Internal sources are planned but not fully implemented in this integration.

Future internal sources include:

```text
Wazuh
honeypot logs
IDS/IPS
Suricata
Zeek
Sysmon
firewall logs
server logs
application logs
```

Expected processing flow:

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
```

Structured security logs should not be forced through the external document classifier. Classification is only appropriate for internal records that contain significant unstructured natural-language text, such as analyst notes or incident reports.

Current extension point:

```text
backend/app/pipeline/ingestion/internal/base_internal_connector.py
```
