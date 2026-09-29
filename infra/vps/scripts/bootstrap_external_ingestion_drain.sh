#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "bootstrap_external_ingestion_drain.sh must run as root" >&2
  exit 1
fi

release_root=${1:?Usage: bootstrap_external_ingestion_drain.sh RELEASE_ROOT}
central_env=/etc/cti-platform/central.env
integration_env=/opt/cti-platform/clients/backend-integrations.env
misp_env=/opt/cti-platform/clients/misp-client.env
lock_pid=

cleanup() {
  if [[ -n ${lock_pid} ]]; then
    kill "${lock_pid}" >/dev/null 2>&1 || true
    wait "${lock_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for path in "${release_root}/compose.yaml" "${release_root}/infra/vps/central.compose.yaml" \
            "${release_root}/infra/vps/scripts/deploy_external_interactive_priority.sh" \
            "${central_env}" "${integration_env}" "${misp_env}"; do
  [[ -s ${path} ]] || { echo "Required input is missing: ${path}" >&2; exit 1; }
done

port=$(sed -n 's/^CTI_BACKEND_PORT=//p' "${central_env}" | tail -n 1)
port=${port:-18000}
mapfile -t backend_ids < <(docker ps --filter "publish=${port}" \
  --filter 'label=com.docker.compose.service=backend' --format '{{.ID}}')
[[ ${#backend_ids[@]} -eq 1 ]] || { echo "Expected exactly one running Backend" >&2; exit 1; }
backend_id=${backend_ids[0]}
project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "${backend_id}")
[[ ${project} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ ]] || { echo "Invalid Backend project" >&2; exit 1; }
mapfile -t db_ids < <(docker ps --filter "label=com.docker.compose.project=${project}" \
  --filter 'label=com.docker.compose.service=db' --format '{{.ID}}')
[[ ${#db_ids[@]} -eq 1 ]] || { echo "Expected exactly one project database" >&2; exit 1; }
db_id=${db_ids[0]}
db_user=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_USER=//p' | tail -n 1)
db_name=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_DB=//p' | tail -n 1)
[[ -n ${db_user} && -n ${db_name} ]] || { echo "Database identity is unavailable" >&2; exit 1; }

# Changing the env file does not affect the running container. It only guarantees
# that the replacement starts disabled after the safe transaction boundary.
cp -a "${integration_env}" "${integration_env}.pre-drain-bootstrap-$(date -u +%Y%m%dT%H%M%SZ)"
if grep -q '^EXTERNAL_INGESTION_WORKER_ENABLED=' "${integration_env}"; then
  sed -i 's/^EXTERNAL_INGESTION_WORKER_ENABLED=.*/EXTERNAL_INGESTION_WORKER_ENABLED=false/' "${integration_env}"
else
  printf '\nEXTERNAL_INGESTION_WORKER_ENABLED=false\n' >>"${integration_env}"
fi

# SHARE waits for the current write transaction to commit, then blocks the next
# claim transaction without changing any row. The worker can be stopped safely
# once this granted lock is visible.
docker exec "${db_id}" psql -v ON_ERROR_STOP=1 -U "${db_user}" -d "${db_name}" -c \
  "BEGIN; LOCK TABLE external_ingestion_operations IN SHARE MODE; SELECT pg_sleep(900); COMMIT;" \
  >/dev/null 2>&1 &
lock_pid=$!
locked=false
for _attempt in $(seq 1 1800); do
  granted=$(docker exec "${db_id}" psql -U "${db_user}" -d "${db_name}" -Atc \
    "SELECT count(*) FROM pg_locks WHERE granted AND mode='ShareLock' AND relation='external_ingestion_operations'::regclass;")
  if [[ ${granted} != 0 ]]; then locked=true; break; fi
  sleep 1
done
[[ ${locked} == true ]] || { echo "Timed out waiting for a safe ingestion boundary" >&2; exit 1; }

docker stop --time 30 "${backend_id}" >/dev/null
cleanup
lock_pid=

export CTI_COMPOSE_PROJECT_NAME=${project}
compose=(docker compose --env-file "${central_env}" --env-file "${integration_env}" \
  --env-file "${misp_env}" -f "${release_root}/compose.yaml" \
  -f "${release_root}/infra/vps/central.compose.yaml")
"${compose[@]}" config --quiet
"${compose[@]}" up -d --no-build --no-deps --force-recreate backend

ready=false
for _attempt in $(seq 1 90); do
  if curl --fail --silent --max-time 5 "http://127.0.0.1:${port}/api/v1/health" >/dev/null 2>&1; then
    ready=true; break
  fi
  sleep 2
done
[[ ${ready} == true ]] || { echo "Disabled Backend did not become healthy" >&2; exit 1; }

exec bash "${release_root}/infra/vps/scripts/deploy_external_interactive_priority.sh" deploy "${release_root}"
