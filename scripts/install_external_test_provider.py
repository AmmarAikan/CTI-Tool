from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from backend.app.pipeline.ingestion.external.application.dark_web_discovery import load_discovery_providers

TARGET = Path("config/dark_web_discovery_providers.external-test.local.json")

def main() -> int:
    parser = argparse.ArgumentParser(description="Install an approved isolated discovery configuration without network access")
    parser.add_argument("source", type=Path); parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    source = args.source
    if source.is_symlink() or not source.is_file(): raise SystemExit("configuration rejected: unsafe source")
    details = source.stat()
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o022:
        raise SystemExit("configuration rejected: unsafe ownership or permissions")
    payload = source.read_bytes()
    if hashlib.sha256(payload).hexdigest() != args.sha256.lower(): raise SystemExit("configuration rejected: checksum mismatch")
    value = json.loads(payload)
    if not isinstance(value, dict) or value.get("schema_version") != "1.0": raise SystemExit("configuration rejected: schema")
    with tempfile.NamedTemporaryFile(dir=TARGET.parent, prefix=".provider-", delete=False) as handle:
        handle.write(payload); temporary = Path(handle.name)
    try:
        os.chmod(temporary, 0o600)
        providers = load_discovery_providers(temporary)
        if not providers or not all(provider.enabled and provider.through_tor and provider.search_endpoint.startswith("https://") for provider in providers):
            raise SystemExit("configuration rejected: provider must be explicitly enabled through Tor")
        os.replace(temporary, TARGET); os.chmod(TARGET, 0o600)
    finally:
        if temporary.exists(): temporary.unlink()
    print("provider_configuration=installed validation=passed network_requests=0")
    return 0

if __name__ == "__main__": raise SystemExit(main())
