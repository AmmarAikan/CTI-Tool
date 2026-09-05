#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run_external_collection.sh must run as root" >&2
  exit 1
fi

exec 9>/run/cti-external-collection.lock
if ! flock -n 9; then
  echo "external collection is already running" >&2
  exit 0
fi

secret_file=/etc/cti-platform/vps.env
if [[ ! -r "${secret_file}" ]]; then
  echo "VPS secret file is unavailable" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${secret_file}"
set +a

base_url=http://127.0.0.1:8090/api/v1/external-sources
gateway_url=http://127.0.0.1:8088/api/v1/external-feed/publish
work_dir=$(mktemp -d /run/cti-external-collection.XXXXXX)
trap 'rm -rf -- "${work_dir}"' EXIT

auth_header="Authorization: Bearer ${EXTERNAL_CONTROL_TOKEN}"
publish_header="Authorization: Bearer ${FEED_PUBLISH_TOKEN}"

curl --fail --silent --show-error --max-time 15 "${base_url}/health" >/dev/null

command_key="scheduled-$(date -u +%Y%m%dT%H%M%SZ)"
curl --fail-with-body --silent --show-error --max-time 30 \
  -X POST \
  -H "${auth_header}" \
  -H "Idempotency-Key: ${command_key}" \
  -H "Content-Type: application/json" \
  --data '{"scope":"all_enabled","force":false}' \
  "${base_url}/jobs" >"${work_dir}/job.json"

job_id=$(python3 - "${work_dir}/job.json" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
job_id = value.get("job_id")
if not isinstance(job_id, str) or len(job_id) < 10:
    raise SystemExit("collector did not return a valid job id")
print(job_id)
PY
)

state=queued
for _attempt in $(seq 1 360); do
  curl --fail-with-body --silent --show-error --max-time 30 \
    -H "${auth_header}" \
    "${base_url}/jobs/${job_id}" >"${work_dir}/status.json"
  state=$(python3 - "${work_dir}/status.json" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(value.get("state", "invalid"))
PY
)
  case "${state}" in
    completed|partial|failed|cancelled) break ;;
    queued|running|cancellation_requested) sleep 5 ;;
    *) echo "collector returned an invalid job state" >&2; exit 1 ;;
  esac
done

if [[ "${state}" != "completed" && "${state}" != "partial" ]]; then
  echo "external collection ended in state=${state}" >&2
  exit 1
fi

curl --fail-with-body --silent --show-error --max-time 60 \
  -H "${auth_header}" \
  "${base_url}/exports/latest" >"${work_dir}/export.json"

curl --fail-with-body --silent --show-error --max-time 120 \
  -X POST \
  -H "${publish_header}" \
  -H "Content-Type: application/json" \
  --data-binary "@${work_dir}/export.json" \
  "${gateway_url}" >"${work_dir}/publish.json"

python3 - "${work_dir}/publish.json" "${state}" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("status") != "accepted":
    raise SystemExit("Gateway did not accept the external export")
print(
    "external collection published "
    f"state={sys.argv[2]} items={int(value.get('item_count', 0))} "
    f"etag={str(value.get('etag', ''))[:12]}"
)
PY
