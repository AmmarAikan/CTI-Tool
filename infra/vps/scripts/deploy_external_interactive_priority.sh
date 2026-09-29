#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "deploy_external_interactive_priority.sh must run as root" >&2
  exit 1
fi

mode=${1:-deploy}
release_root=${2:-/opt/cti-platform/current}
central_env=/etc/cti-platform/central.env
integration_env=/opt/cti-platform/clients/backend-integrations.env
misp_env=/opt/cti-platform/clients/misp-client.env
vps_env=/etc/cti-platform/vps.env
state_root=/opt/cti-platform/deployments/external-interactive-priority

read_env_value() {
  local file=$1 key=$2
  sed -n "s/^${key}=//p" "${file}" | tail -n 1
}

if [[ ${mode} == rollback ]]; then
  state_dir=${2:-}
  if [[ -z ${state_dir} || ! -s ${state_dir}/state.env ]]; then
    echo "Usage: $0 rollback /opt/cti-platform/deployments/external-interactive-priority/<timestamp>" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "${state_dir}/state.env"
  cp -- "${state_dir}/cti-external-collect-publish" /usr/local/sbin/cti-external-collect-publish
  chmod 0755 /usr/local/sbin/cti-external-collect-publish
  docker image tag "${BACKEND_ROLLBACK_IMAGE}" cti-central-backend:current
  docker image tag "${GATEWAY_ROLLBACK_IMAGE}" cti-vps-gateway:1.0.0
  docker compose --env-file "${vps_env}" -f "${RELEASE_ROOT}/infra/vps/compose.yaml" up -d --no-build --no-deps gateway
  docker compose --env-file "${central_env}" --env-file "${integration_env}" --env-file "${misp_env}" \
    -f "${RELEASE_ROOT}/compose.yaml" -f "${RELEASE_ROOT}/infra/vps/central.compose.yaml" \
    up -d --no-build --no-deps backend
  echo "Rollback completed; database and Gateway data were not modified."
  exit 0
fi

if [[ ${mode} != deploy ]]; then
  echo "Usage: $0 [deploy [release-root] | rollback state-directory]" >&2
  exit 1
fi

required=(
  "${release_root}/compose.yaml"
  "${release_root}/infra/vps/central.compose.yaml"
  "${release_root}/infra/vps/compose.yaml"
  "${release_root}/infra/vps/scripts/run_external_collection.sh"
  "${central_env}" "${integration_env}" "${misp_env}" "${vps_env}"
)
for path in "${required[@]}"; do
  if [[ ! -s ${path} ]]; then
    echo "Required deployment input is missing or empty: ${path}" >&2
    exit 1
  fi
done

# This deployment intentionally preserves the disabled worker state. Enabling it
# is a separate operator decision after the new images and contracts are healthy.
worker_flag=$(read_env_value "${integration_env}" EXTERNAL_INGESTION_WORKER_ENABLED)
if [[ ${worker_flag,,} != false && ${worker_flag} != 0 ]]; then
  echo "EXTERNAL_INGESTION_WORKER_ENABLED must be explicitly false before deployment" >&2
  exit 1
fi
if systemctl is-active --quiet cti-external-collection.service; then
  echo "A scheduled External collection is running; deployment refused" >&2
  exit 1
fi

backend_port=$(read_env_value "${central_env}" CTI_BACKEND_PORT)
backend_port=${backend_port:-18000}
mapfile -t backend_ids < <(docker ps --filter "publish=${backend_port}" \
  --filter 'label=com.docker.compose.service=backend' --format '{{.ID}}')
mapfile -t gateway_ids < <(docker ps --filter 'publish=8088' \
  --filter 'label=com.docker.compose.service=gateway' --format '{{.ID}}')
if [[ ${#backend_ids[@]} -ne 1 || ${#gateway_ids[@]} -ne 1 ]]; then
  echo "Expected exactly one Backend on port ${backend_port} and one Gateway on port 8088" >&2
  exit 1
fi
backend_id=${backend_ids[0]}; gateway_id=${gateway_ids[0]}
project_name=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "${backend_id}")
if [[ -z ${project_name} || ! ${project_name} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ ]]; then
  echo "Unable to resolve the running Backend Compose project" >&2
  exit 1
fi
mapfile -t db_ids < <(docker ps --filter "label=com.docker.compose.project=${project_name}" \
  --filter 'label=com.docker.compose.service=db' --format '{{.ID}}')
if [[ ${#db_ids[@]} -ne 1 ]]; then
  echo "Expected exactly one database in the running Backend project ${project_name}" >&2
  exit 1
fi
db_id=${db_ids[0]}
# The running project is authoritative. This avoids accidentally creating a
# parallel stack when an older central.env contains a stale project name.
export CTI_COMPOSE_PROJECT_NAME=${project_name}
db_user=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_USER=//p' | tail -n 1)
db_name=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_DB=//p' | tail -n 1)
if [[ -z ${db_user} || -z ${db_name} ]]; then
  echo "Unable to resolve database identity" >&2
  exit 1
fi

# Read-only safety checks: required schema exists, and no live claim can be cut.
columns=$(docker exec "${db_id}" psql -U "${db_user}" -d "${db_name}" -Atc \
  "SELECT count(*) FROM information_schema.columns WHERE table_name='external_ingestion_operations' AND column_name IN ('priority','processed_offset','claim_token','lease_expires_at');")
if [[ ${columns} != 4 ]]; then
  echo "Required ingestion schema is absent; this script will not change the database" >&2
  exit 1
fi
active_claims=$(docker exec "${db_id}" psql -U "${db_user}" -d "${db_name}" -Atc \
  "SELECT count(*) FROM external_ingestion_operations WHERE claim_token IS NOT NULL AND (lease_expires_at IS NULL OR lease_expires_at > CURRENT_TIMESTAMP);")
if [[ ${active_claims} != 0 ]]; then
  echo "An ingestion operation has a live claim; deployment refused" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${vps_env}"
set +a
jobs_file=$(mktemp /run/cti-external-jobs.XXXXXX)
trap 'rm -f -- "${jobs_file}"' EXIT
curl --fail --silent --show-error --max-time 20 \
  -H "Authorization: Bearer ${EXTERNAL_CONTROL_TOKEN}" \
  'http://127.0.0.1:8090/api/v1/external-sources/jobs?limit=100' >"${jobs_file}"
python3 - "${jobs_file}" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
active = [item.get("job_id") for item in value.get("jobs", [])
          if item.get("state") in {"queued", "running", "cancellation_requested"}]
if active:
    raise SystemExit("External collection jobs are active; deployment refused")
PY

python_bin=/opt/cti-platform/src/cti-platform/.venv/bin/python
if [[ ! -x ${python_bin} ]]; then
  echo "Production test interpreter is unavailable" >&2
  exit 1
fi
(
  cd "${release_root}"
  PYTHONWARNINGS=ignore "${python_bin}" -m unittest \
    tests.test_external_ingestion_operations \
    tests.test_backend_external_feed_batching \
    tests.test_vps_gateway -q
)

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
state_dir="${state_root}/${timestamp}"
install -d -o root -g root -m 0700 "${state_dir}"
backend_rollback="cti-central-backend:interactive-priority-rollback-${timestamp}"
gateway_rollback="cti-vps-gateway:interactive-priority-rollback-${timestamp}"
docker image tag "$(docker inspect --format '{{.Image}}' "${backend_id}")" "${backend_rollback}"
docker image tag "$(docker inspect --format '{{.Image}}' "${gateway_id}")" "${gateway_rollback}"
cp -- /usr/local/sbin/cti-external-collect-publish "${state_dir}/cti-external-collect-publish"
cat >"${state_dir}/state.env" <<EOF
RELEASE_ROOT=${release_root}
BACKEND_ROLLBACK_IMAGE=${backend_rollback}
GATEWAY_ROLLBACK_IMAGE=${gateway_rollback}
EOF
chmod 0600 "${state_dir}/state.env" "${state_dir}/cti-external-collect-publish"

vps_compose=(docker compose --env-file "${vps_env}" -f "${release_root}/infra/vps/compose.yaml")
central_compose=(docker compose --env-file "${central_env}" --env-file "${integration_env}" \
  --env-file "${misp_env}" -f "${release_root}/compose.yaml" \
  -f "${release_root}/infra/vps/central.compose.yaml")
"${vps_compose[@]}" config --quiet
"${central_compose[@]}" config --quiet
"${vps_compose[@]}" build gateway
"${central_compose[@]}" build backend
install -o root -g root -m 0755 "${release_root}/infra/vps/scripts/run_external_collection.sh" \
  /usr/local/sbin/cti-external-collect-publish
"${vps_compose[@]}" up -d --no-deps gateway
"${central_compose[@]}" up -d --no-deps backend

for endpoint in 'http://127.0.0.1:8088/health' "http://127.0.0.1:${backend_port}/api/v1/health"; do
  ready=false
  for _attempt in $(seq 1 60); do
    if curl --fail --silent --show-error --max-time 5 "${endpoint}" >/dev/null; then ready=true; break; fi
    sleep 2
  done
  if [[ ${ready} != true ]]; then
    echo "Post-deployment health check failed: ${endpoint}" >&2
    echo "Rollback: sudo bash ${release_root}/infra/vps/scripts/deploy_external_interactive_priority.sh rollback ${state_dir}" >&2
    exit 1
  fi
done

if [[ $(read_env_value "${integration_env}" EXTERNAL_INGESTION_WORKER_ENABLED) != false ]]; then
  echo "Worker configuration changed unexpectedly; review and rollback" >&2
  exit 1
fi
echo "Deployment healthy. Worker remains disabled."
echo "Checkpoint: ${state_dir}"
echo "Rollback: sudo bash ${release_root}/infra/vps/scripts/deploy_external_interactive_priority.sh rollback ${state_dir}"
