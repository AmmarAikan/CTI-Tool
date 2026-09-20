#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${PYTHON:-}" ]]; then
  python_command="${PYTHON}"
elif command -v python3 >/dev/null 2>&1; then
  python_command="python3"
else
  python_command="python"
fi
pycache_root="$(mktemp -d /tmp/cti-external-pycache.XXXXXX)"
trap 'rm -rf -- "${pycache_root}"' EXIT

cd -- "${repository_root}"

timeout 15m "${python_command}" -m unittest discover -s tests/external_sources -p 'test_*.py' -v
timeout 10m "${python_command}" -m unittest \
  tests.test_external_pipeline \
  tests.test_external_control_client \
  tests.test_external_image_permissions \
  tests.test_external_test_compose \
  -v
PYTHONPYCACHEPREFIX="${pycache_root}" \
  timeout 5m "${python_command}" -m compileall -q backend/app/pipeline/ingestion/external

cd -- "${repository_root}/frontend"
timeout 10m npm ci
timeout 5m npm run lint
timeout 10m npm test
timeout 10m npm run build
