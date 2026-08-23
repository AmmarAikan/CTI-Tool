# CTI Tool Repository Instructions

## Purpose and ownership

This is a shared multi-team Cyber Threat Intelligence repository. External Sources owns collection, extraction of source text and metadata, privacy handling, incremental External state, External-only deduplication, and versioned JSON handoff artifacts.

External Sources does not own Internal Sources, NER, IoC extraction, relation extraction, central persistence, dashboard code, or model training.

## Important paths

- `backend/app/pipeline/ingestion/external/`: sole final External Sources implementation.
- `backend/app/pipeline/common/`: shared contracts; change only after reporting and approval.
- `backend/app/pipeline/preprocessing/`: approved shared preprocessing; reuse rather than duplicate.
- `contracts/`: versioned External handoff and integration schemas.
- `config/`: committed non-secret configuration.
- `data/external/`: local External runtime state and outputs, not central persistence.
- `tests/external_sources/`: deterministic External Sources tests.
- `src/`: replaceable External prototype; do not extend or delete without an approved migration step.

## Environment and commands

- Supported Python: 3.11 or newer.
- Setup: `python -m pip install -r requirements.txt`
- Full tests: `python -m unittest discover -v`
- External Phase 0 tests: `python -m unittest discover -s tests/external_sources -p "test_*.py" -v`
- Compile check: `python -m compileall backend/app/pipeline/ingestion/external`
- Authorized maintenance entry points must call the same application services as future production adapters.

## Engineering conventions

- Use typed, deterministic, independently testable modules.
- Use UTC ISO-8601 timestamps ending in `Z`.
- Use SHA-256 and canonical serialization for persistent identities.
- Use atomic writes for state and exports.
- Isolate per-source and per-item failures and record safe errors without secrets.
- Keep collectors independently configurable and bounded.
- Never create a second final implementation under `src/`.

## Contracts and team boundaries

- External connectors implement the shared `ExternalConnector` interface and map accepted items to `RawRecord`.
- External exports must validate against the versioned schemas under `contracts/`.
- Required nullable fields remain present.
- Source-specific fields belong in `metadata`.
- External deduplication must preserve provenance and must not perform cross-team deduplication.
- Report any required change to a shared or other-team module before editing it, including affected consumers and compatibility tests.

## User interface and prohibited features

The dashboard is the sole production end-user interface. CLI/module access is restricted to development, automated testing, authorized maintenance, diagnostics, and emergency recovery.

Do not implement a dashboard, central database, public API during collector phases, Internal Sources, NER, IoC extraction, correlation, enrichment, or model training. Never commit secrets, local onion-source lists, generated datasets, or private browser state.

## Phase definition of done

A phase is complete only when its approved scope is implemented, contracts/configuration and documentation are synchronized, deterministic tests pass, live versus mocked verification is reported honestly, shared-team work is preserved, and work stops before the next phase pending explicit approval.
