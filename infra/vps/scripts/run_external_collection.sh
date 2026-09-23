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

current_stage=initialization
job_id=unassigned
command_id=unassigned
invocation_id="${INVOCATION_ID:-unavailable}"
if [[ ! "${invocation_id}" =~ ^[a-fA-F0-9]{32}$ ]]; then
  invocation_id=unavailable
fi
report_error() {
  local status=$?
  echo "external collection failed invocation_id=${invocation_id} job_id=${job_id} command_id=${command_id} stage=${current_stage} exit_status=${status}" >&2
  exit "${status}"
}
trap report_error ERR

auth_header="Authorization: Bearer ${EXTERNAL_CONTROL_TOKEN}"
publish_header="Authorization: Bearer ${FEED_PUBLISH_TOKEN}"

current_stage=health_check
curl --fail --silent --show-error --max-time 15 "${base_url}/health" >/dev/null

current_stage=job_submission
command_key="scheduled-$(date -u +%Y%m%dT%H%M%SZ)"
curl --fail-with-body --silent --show-error --max-time 30 \
  -X POST \
  -H "${auth_header}" \
  -H "Idempotency-Key: ${command_key}" \
  -H "Content-Type: application/json" \
  --data '{"scope":"all_enabled","force":false}' \
  "${base_url}/jobs" >"${work_dir}/job.json"

IFS=$'\t' read -r job_id command_id < <(python3 - "${work_dir}/job.json" <<'PY'
import json
import pathlib
import re
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
job_id = value.get("job_id")
command_id = value.get("command_id")
safe = re.compile(r"^[A-Za-z0-9_-]{10,100}$")
if not isinstance(job_id, str) or not safe.fullmatch(job_id):
    raise SystemExit("collector did not return a valid job id")
if not isinstance(command_id, str) or not safe.fullmatch(command_id):
    raise SystemExit("collector did not return a valid command id")
print(f"{job_id}\t{command_id}")
PY
)
echo "external collection accepted invocation_id=${invocation_id} job_id=${job_id} command_id=${command_id} stage=job_submission"

current_stage=job_polling
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

current_stage=collection_terminal
python3 - "${work_dir}/status.json" "${invocation_id}" "${job_id}" "${command_id}" <<'PY'
from collections import Counter
import json
import pathlib
import re
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
safe_token = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
allowed_states = {"queued", "running", "completed", "partial", "failed", "cancelled", "cancellation_requested"}

state = value.get("state")
if state not in allowed_states:
    state = "invalid"
result = value.get("result") if isinstance(value.get("result"), dict) else {}
sources = result.get("sources") if isinstance(result.get("sources"), dict) else {}
status_counts = Counter()
class_status_counts = Counter()
failure_counts = Counter()
exception_counts = Counter()
for diagnostic in sources.values():
    if not isinstance(diagnostic, dict):
        continue
    status = diagnostic.get("status")
    status = status if status in allowed_states else "invalid"
    status_counts[status] += 1
    source_class = diagnostic.get("collection_method")
    source_class = source_class if isinstance(source_class, str) and safe_token.fullmatch(source_class) else "unknown"
    class_status_counts[f"{source_class}_{status}"] += 1
    categories = diagnostic.get("failure_categories")
    if isinstance(categories, dict):
        for category, count in categories.items():
            if isinstance(category, str) and safe_token.fullmatch(category) and isinstance(count, int) and 0 <= count <= 1_000_000:
                failure_counts[category] += count
    exception = diagnostic.get("exception_class")
    if isinstance(exception, str) and safe_token.fullmatch(exception):
        exception_counts[exception] += 1
error = value.get("error") if isinstance(value.get("error"), dict) else {}
job_failure = error.get("code")
job_failure = job_failure if isinstance(job_failure, str) and safe_token.fullmatch(job_failure) else "none"
export = result.get("export")
export_status = export.get("status") if isinstance(export, dict) else "not_started"
export_status = export_status if isinstance(export_status, str) and safe_token.fullmatch(export_status) else "unknown"

def rendered(counter: Counter[str]) -> str:
    return ",".join(f"{key}:{counter[key]}" for key in sorted(counter)) or "none"

print(
    "external collection terminal "
    f"invocation_id={sys.argv[2]} job_id={sys.argv[3]} command_id={sys.argv[4]} "
    f"stage=collection_terminal state={state} source_count={len(sources)} "
    f"source_status_counts={rendered(status_counts)} "
    f"source_class_status_counts={rendered(class_status_counts)} "
    f"failure_categories={rendered(failure_counts)} "
    f"exception_classes={rendered(exception_counts)} "
    f"export_stage={export_status} job_failure_category={job_failure}"
)
PY

if [[ "${state}" != "completed" && "${state}" != "partial" ]]; then
  echo "external collection stopped invocation_id=${invocation_id} job_id=${job_id} command_id=${command_id} stage=collection_terminal state=${state}" >&2
  exit 1
fi

current_stage=export_retrieval
echo "external collection export invocation_id=${invocation_id} job_id=${job_id} command_id=${command_id} stage=export_retrieval state=started"
curl --fail-with-body --silent --show-error --max-time 60 \
  -H "${auth_header}" \
  "${base_url}/exports/latest" >"${work_dir}/export.json"
echo "external collection export invocation_id=${invocation_id} job_id=${job_id} command_id=${command_id} stage=export_retrieval state=completed"

current_stage=gateway_publish
curl --fail-with-body --silent --show-error --max-time 120 \
  -X POST \
  -H "${publish_header}" \
  -H "Content-Type: application/json" \
  --data-binary "@${work_dir}/export.json" \
  "${gateway_url}" >"${work_dir}/publish.json"

python3 - "${work_dir}/publish.json" "${state}" "${invocation_id}" "${job_id}" "${command_id}" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("status") != "accepted":
    raise SystemExit("Gateway did not accept the external export")
print(
    "external collection published "
    f"invocation_id={sys.argv[3]} job_id={sys.argv[4]} command_id={sys.argv[5]} "
    f"stage=gateway_publish state={sys.argv[2]} items={int(value.get('item_count', 0))} "
    f"etag={str(value.get('etag', ''))[:12]}"
)
PY
