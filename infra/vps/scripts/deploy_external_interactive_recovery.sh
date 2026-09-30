#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "deploy_external_interactive_recovery.sh must run as root" >&2
  exit 1
fi

mode=${1:-deploy}
release_root=${2:-}
central_env=/etc/cti-platform/central.env
integration_env=/opt/cti-platform/clients/backend-integrations.env
misp_env=/opt/cti-platform/clients/misp-client.env
vps_env=/etc/cti-platform/vps.env
state_root=/opt/cti-platform/deployments/external-interactive-recovery

read_env_value() { sed -n "s/^${2}=//p" "${1}" | tail -n 1; }
set_env_value() {
  local file=$1 key=$2 value=$3
  if grep -q "^${key}=" "${file}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    printf '\n%s=%s\n' "${key}" "${value}" >>"${file}"
  fi
}

sync_publish_token() {
  local value
  value=$(read_env_value "${vps_env}" FEED_PUBLISH_TOKEN)
  [[ -n ${value} ]] || { echo "FEED_PUBLISH_TOKEN is missing; deployment refused" >&2; exit 1; }
  set_env_value "${integration_env}" EXTERNAL_FEED_PUBLISH_TOKEN "${value}"
  chmod 0600 "${integration_env}"
}

resolve_runtime() {
  backend_port=$(read_env_value "${central_env}" CTI_BACKEND_PORT); backend_port=${backend_port:-18000}
  frontend_port=$(read_env_value "${central_env}" CTI_FRONTEND_PORT); frontend_port=${frontend_port:-18080}
  mapfile -t backend_ids < <(docker ps --filter "publish=${backend_port}" --filter 'label=com.docker.compose.service=backend' --format '{{.ID}}')
  mapfile -t frontend_ids < <(docker ps --filter "publish=${frontend_port}" --filter 'label=com.docker.compose.service=frontend' --format '{{.ID}}')
  mapfile -t gateway_ids < <(docker ps --filter 'publish=8088' --filter 'label=com.docker.compose.service=gateway' --format '{{.ID}}')
  [[ ${#backend_ids[@]} -eq 1 && ${#frontend_ids[@]} -eq 1 && ${#gateway_ids[@]} -eq 1 ]] || {
    echo "Expected exactly one Backend, frontend, and Gateway" >&2; exit 1;
  }
  backend_id=${backend_ids[0]}; frontend_id=${frontend_ids[0]}; gateway_id=${gateway_ids[0]}
  project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "${backend_id}")
  [[ ${project} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ ]] || { echo "Invalid Backend project" >&2; exit 1; }
  mapfile -t db_ids < <(docker ps --filter "label=com.docker.compose.project=${project}" --filter 'label=com.docker.compose.service=db' --format '{{.ID}}')
  [[ ${#db_ids[@]} -eq 1 ]] || { echo "Expected exactly one project database" >&2; exit 1; }
  db_id=${db_ids[0]}
  db_user=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_USER=//p' | tail -1)
  db_name=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_DB=//p' | tail -1)
  export CTI_COMPOSE_PROJECT_NAME=${project}
}

compose_runtime() {
  central_compose=(docker compose --env-file "${central_env}" --env-file "${integration_env}" \
    --env-file "${misp_env}" -f "${release_root}/compose.yaml" \
    -f "${release_root}/infra/vps/central.compose.yaml")
}

if [[ ${mode} == rollback ]]; then
  state_dir=${2:-}
  [[ -s ${state_dir}/state.env ]] || { echo "Usage: $0 rollback STATE_DIRECTORY" >&2; exit 1; }
  # shellcheck disable=SC1090
  source "${state_dir}/state.env"
  release_root=${RELEASE_ROOT}
  bash "${release_root}/infra/vps/scripts/deploy_external_worker_client_fix.sh" rollback "${BASE_CHECKPOINT}"
  resolve_runtime
  docker image tag "${FRONTEND_ROLLBACK_IMAGE}" cti-central-frontend:current
  compose_runtime
  "${central_compose[@]}" up -d --no-build --no-deps --force-recreate frontend
  echo "Rollback completed. The backlog archive was retained at ${BACKLOG_ARCHIVE:-${state_dir}/backlog-archive}."
  exit 0
fi

[[ ${mode} == deploy && -n ${release_root} ]] || { echo "Usage: $0 deploy RELEASE_ROOT" >&2; exit 1; }
for path in "${release_root}/infra/vps/scripts/deploy_external_worker_client_fix.sh" \
            "${release_root}/compose.yaml" "${release_root}/infra/vps/central.compose.yaml" \
            "${central_env}" "${integration_env}" "${misp_env}" "${vps_env}"; do
  [[ -s ${path} ]] || { echo "Required input is missing: ${path}" >&2; exit 1; }
done

resolve_runtime
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
state_dir=${state_root}/${timestamp}
archive_dir=${state_dir}/backlog-archive
install -d -o root -g root -m 0700 "${state_dir}"
frontend_rollback=cti-central-frontend:interactive-recovery-rollback-${timestamp}
docker image tag "$(docker inspect --format '{{.Image}}' "${frontend_id}")" "${frontend_rollback}"

# The Gateway publish credential is authoritative in the root-only VPS env.
# Synchronize it without printing it before any Backend image is recreated.
sync_publish_token

# Copy the immutable-at-write Gateway artifacts without acknowledging, deleting,
# or moving them. A before/after digest refuses an archive made during mutation.
before=$(docker exec "${gateway_id}" sh -c 'find /data -maxdepth 2 -type f \( -name "external_feed.json" -o -name "external_feed_delivery.json" -o -path "/data/external_feed_batches/*.json" \) -exec sha256sum {} \; 2>/dev/null | sort')
[[ -n ${before} ]] || { echo "No Gateway External backlog artifacts were found" >&2; exit 1; }

# Reuse the newest verified archive when the complete Gateway artifact digest
# is unchanged. This avoids copying the quarantined backlog on every release.
reused_archive=
while IFS= read -r digest_file; do
  candidate=${digest_file%/gateway-source-sha256.txt}
  if printf '%s\n' "${before}" | cmp -s - "${digest_file}" \
      && [[ -s ${candidate}/manifest.sha256 ]] \
      && (cd "${candidate}" && sha256sum -c manifest.sha256 >/dev/null 2>&1); then
    reused_archive=${candidate}
    break
  fi
done < <(find "${state_root}" -mindepth 3 -maxdepth 3 -type f \
  -path '*/backlog-archive/gateway-source-sha256.txt' -print | sort -r)

if [[ -n ${reused_archive} ]]; then
  archive_dir=${reused_archive}
  echo "Gateway backlog unchanged; reusing verified archive: ${archive_dir}"
else
  install -d -o root -g root -m 0700 "${archive_dir}"
  docker cp "${gateway_id}:/data/external_feed.json" "${archive_dir}/external_feed.json"
  if docker exec "${gateway_id}" test -f /data/external_feed_delivery.json; then
    docker cp "${gateway_id}:/data/external_feed_delivery.json" "${archive_dir}/external_feed_delivery.json"
  fi
  if docker exec "${gateway_id}" test -d /data/external_feed_batches; then
    docker cp "${gateway_id}:/data/external_feed_batches" "${archive_dir}/external_feed_batches"
  fi
fi
after=$(docker exec "${gateway_id}" sh -c 'find /data -maxdepth 2 -type f \( -name "external_feed.json" -o -name "external_feed_delivery.json" -o -path "/data/external_feed_batches/*.json" \) -exec sha256sum {} \; 2>/dev/null | sort')
[[ ${before} == "${after}" ]] || { echo "Gateway backlog changed during archival; deployment refused" >&2; exit 1; }
docker exec "${db_id}" psql -X -U "${db_user}" -d "${db_name}" -P pager=off -c \
  "SELECT id, external_job_id, export_run_id, dataset_sha256, priority, state, stage,
          exported_count, processed_offset, acknowledged_count, error_code, updated_at
     FROM external_ingestion_operations WHERE priority <= 0 ORDER BY created_at;" \
  >"${state_dir}/database-operations.txt"
if [[ -z ${reused_archive} ]]; then
  printf '%s\n' "${before}" >"${archive_dir}/gateway-source-sha256.txt"
  cp "${state_dir}/database-operations.txt" "${archive_dir}/database-operations.txt"
  (cd "${archive_dir}" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
fi

base_log=${state_dir}/base-deployment.log
bash "${release_root}/infra/vps/scripts/deploy_external_worker_client_fix.sh" deploy "${release_root}" | tee "${base_log}"
base_checkpoint=$(sed -n 's/^Checkpoint: //p' "${base_log}" | tail -1)
[[ -s ${base_checkpoint}/state.env ]] || { echo "Base deployment checkpoint is missing" >&2; exit 1; }
cat >"${state_dir}/state.env" <<EOF
RELEASE_ROOT=${release_root}
BASE_CHECKPOINT=${base_checkpoint}
FRONTEND_ROLLBACK_IMAGE=${frontend_rollback}
BACKLOG_ARCHIVE=${archive_dir}
EOF
chmod 0600 "${state_dir}/state.env"
rollback_command="sudo bash ${release_root}/infra/vps/scripts/deploy_external_interactive_recovery.sh rollback ${state_dir}"
trap 'echo "Deployment did not complete. Rollback: ${rollback_command}" >&2' ERR

# Quarantine only priority-zero Gateway backlog. Interactive operations remain
# enabled and preserve their exact export identity and retry lifecycle.
set_env_value "${integration_env}" EXTERNAL_INGESTION_BACKLOG_ENABLED false
resolve_runtime
compose_runtime
"${central_compose[@]}" config --quiet
"${central_compose[@]}" build frontend
"${central_compose[@]}" up -d --no-build --no-deps --force-recreate backend frontend

for endpoint in "http://127.0.0.1:${backend_port}/api/v1/health" "http://127.0.0.1:${frontend_port}/"; do
  ready=false
  for _attempt in $(seq 1 90); do
    if curl --fail --silent --max-time 5 "${endpoint}" >/dev/null 2>&1; then ready=true; break; fi
    sleep 2
  done
  [[ ${ready} == true ]] || { echo "Post-deployment health failed: ${endpoint}" >&2; exit 1; }
done

backend_id=$(docker ps --filter "publish=${backend_port}" --filter 'label=com.docker.compose.service=backend' --format '{{.ID}}')
docker exec "${backend_id}" python -c \
  'from backend.app.core.config import get_settings; from backend.app.integrations.external_control_client import configured_external_control_client; s=get_settings(); assert s.external_ingestion_worker_enabled and not s.external_ingestion_backlog_enabled and s.external_feed_publish_token; assert configured_external_control_client() is not None'

if [[ -z ${reused_archive} ]]; then
  find "${archive_dir}" -type d -exec chmod 0700 {} +
  find "${archive_dir}" -type f -exec chmod 0600 {} +
fi
chmod 0600 "${state_dir}/database-operations.txt"
trap - ERR
echo "Deployment healthy. Interactive worker enabled; priority-zero backlog quarantined."
echo "Backlog archive: ${archive_dir}"
echo "The existing failed interactive operations were preserved and not retried automatically."
echo "Checkpoint: ${state_dir}"
echo "Rollback: ${rollback_command}"
