# Integration Notes

## What Was Integrated

The prepared `p2/` JSON files are treated as external source inputs. They are not copied over the project root and they do not create a duplicate backend.

New backend runtime modules add:

```text
common CTI schema
external connector contract
prepared JSON file connector
RSS connector scaffold
NVD structured-record connector
internal connector scaffold
text cleaning and normalization
deduplication
document relevance classification
regex IoC extraction
rule-based relation extraction
external pipeline orchestrator
```

## Current Limitations

The document classifier currently uses a rule-based fallback unless a sklearn classifier path is provided through `CTI_CLASSIFIER_MODEL_PATH`.

Relation extraction is rule-based and intentionally conservative. It should not be described as ML-based.

No persistence layer is implemented yet. The orchestrator returns normalized CTI objects in memory or prints them as JSON from the CLI.

The internal runtime path is an interface only. Wazuh, Suricata, Zeek, and honeypot processing remain future work.

## Error Handling

Batch processing catches per-record failures and emits a failed CTI object with:

```text
processing_status=failed
processing_errors[].stage
processing_errors[].message
processing_errors[].connector_name
processing_errors[].source_record_id
```

## Secrets

API keys, tokens, credentials, local virtual environments, large model checkpoints, and archives must not be committed. Existing `.gitignore` already excludes the local BERT model directory, virtual environments, and archives.
