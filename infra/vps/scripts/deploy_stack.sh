#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "deploy_stack.sh must run as root" >&2
  exit 1
fi

release_root="${1:-/opt/cti-platform/current}"
vps_dir="${release_root}/infra/vps"
if [[ ! -f "${vps_dir}/compose.yaml" || ! -d "${release_root}/infra/dionaea" ]]; then
  echo "Release root is missing infra/vps or infra/dionaea: ${release_root}" >&2
  exit 1
fi

install -d -m 0750 /etc/cti-platform
secret_file=/etc/cti-platform/vps.env
if [[ ! -s "${secret_file}" ]]; then
  umask 077
  cat > "${secret_file}" <<EOF
FEED_PUBLISH_TOKEN=$(openssl rand -hex 32)
FEED_READ_TOKEN=$(openssl rand -hex 32)
FEED_RESPONSE_HMAC_SECRET=$(openssl rand -hex 32)
SENSOR_READ_TOKEN=$(openssl rand -hex 32)
SENSOR_RESPONSE_HMAC_SECRET=$(openssl rand -hex 32)
CURSOR_HMAC_SECRET=$(openssl rand -hex 32)
EXTERNAL_CONTROL_TOKEN=$(openssl rand -hex 32)
EXTERNAL_FEED_ID=external-team-feed
SENSOR_ID=cti-vps
SENSOR_READ_GID=31002
MAX_PUBLISH_BYTES=20971520
MAX_SENSOR_BYTES=52428800
MAX_FEED_ITEMS=20000
EXTERNAL_API_DEV_WORKERS=2
EXTERNAL_DARK_WEB_CONFIG_FILE=/etc/cti-platform/dark_web_sources.json
EOF
fi
chmod 0600 "${secret_file}"

if ! grep -q '^EXTERNAL_CONTROL_TOKEN=' "${secret_file}"; then
  printf 'EXTERNAL_CONTROL_TOKEN=%s\n' "$(openssl rand -hex 32)" >>"${secret_file}"
fi
if ! grep -q '^EXTERNAL_API_DEV_WORKERS=' "${secret_file}"; then
  printf '%s\n' 'EXTERNAL_API_DEV_WORKERS=2' >>"${secret_file}"
fi
if ! grep -q '^EXTERNAL_DARK_WEB_CONFIG_FILE=' "${secret_file}"; then
  printf '%s\n' 'EXTERNAL_DARK_WEB_CONFIG_FILE=/etc/cti-platform/dark_web_sources.json' >>"${secret_file}"
fi

dark_web_config=/etc/cti-platform/dark_web_sources.json
if [[ ! -e "${dark_web_config}" ]]; then
  install -o root -g root -m 0600 \
    "${release_root}/config/dark_web_sources.example.json" "${dark_web_config}"
fi

if ! getent group cti-sensor-read >/dev/null; then
  groupadd --system --gid 31002 cti-sensor-read
fi
install -d -o root -g cti-sensor-read -m 2750 /var/lib/cti-sensors
install -d -o root -g root -m 0755 /opt/cti-sensors
install -o root -g root -m 0755 "${vps_dir}/collectors/ssh_journal_collector.py" /opt/cti-sensors/ssh_journal_collector.py
install -o root -g root -m 0644 "${vps_dir}/systemd/cti-ssh-collector.service" /etc/systemd/system/cti-ssh-collector.service
install -o root -g root -m 0644 "${vps_dir}/systemd/cti-ssh-collector.timer" /etc/systemd/system/cti-ssh-collector.timer
install -o root -g root -m 0644 "${vps_dir}/logrotate/cti-sensors" /etc/logrotate.d/cti-sensors
install -o root -g root -m 0755 "${vps_dir}/scripts/apply_docker_firewall.sh" /usr/local/sbin/cti-apply-docker-firewall
install -o root -g root -m 0755 "${vps_dir}/scripts/run_external_collection.sh" /usr/local/sbin/cti-external-collect-publish
install -o root -g root -m 0755 "${vps_dir}/scripts/maintain_storage.sh" /usr/local/sbin/cti-maintain-storage
install -o root -g root -m 0644 "${vps_dir}/systemd/cti-docker-firewall.service" /etc/systemd/system/cti-docker-firewall.service
install -o root -g root -m 0644 "${vps_dir}/systemd/cti-external-collection.service" /etc/systemd/system/cti-external-collection.service
install -o root -g root -m 0644 "${vps_dir}/systemd/cti-external-collection.timer" /etc/systemd/system/cti-external-collection.timer
install -o root -g root -m 0644 "${vps_dir}/systemd/cti-storage-maintenance.service" /etc/systemd/system/cti-storage-maintenance.service
install -o root -g root -m 0644 "${vps_dir}/systemd/cti-storage-maintenance.timer" /etc/systemd/system/cti-storage-maintenance.timer
install -o root -g root -m 0644 "${vps_dir}/logrotate/cti-dionaea-container" /etc/logrotate.d/cti-dionaea-container

systemctl daemon-reload
systemctl enable --now cti-ssh-collector.timer
systemctl start cti-ssh-collector.service

docker compose --env-file "${secret_file}" -f "${vps_dir}/compose.yaml" build
docker compose --env-file "${secret_file}" -f "${vps_dir}/compose.yaml" up -d
systemctl enable --now cti-docker-firewall.service
systemctl enable --now cti-storage-maintenance.timer

# Produce the least-privilege Ammar client fragment without exposing values in
# command output. External publishing now occurs locally on the VPS host.
set -a
# shellcheck disable=SC1090
source "${secret_file}"
set +a
install -d -o root -g ammar -m 0750 /opt/cti-platform/clients
umask 027
cat > /opt/cti-platform/clients/ammar-backend.env <<EOF
EXTERNAL_FEED_URL=http://host.docker.internal:18088/api/v1/external-feed
EXTERNAL_FEED_TOKEN=${FEED_READ_TOKEN}
EXTERNAL_FEED_HMAC_SECRET=${FEED_RESPONSE_HMAC_SECRET}
EXTERNAL_FEED_VERIFY_TLS=false
EXTERNAL_FEED_ALLOW_HTTP=true
DIONAEA_API_URL=http://host.docker.internal:18088/api/v1/sensors/dionaea
DIONAEA_API_TOKEN=${SENSOR_READ_TOKEN}
DIONAEA_API_HMAC_SECRET=${SENSOR_RESPONSE_HMAC_SECRET}
DIONAEA_API_VERIFY_TLS=false
DIONAEA_API_ALLOW_HTTP=true
INTERNAL_SENSOR_API_TOKEN=${SENSOR_READ_TOKEN}
INTERNAL_SENSOR_API_HMAC_SECRET=${SENSOR_RESPONSE_HMAC_SECRET}
INTERNAL_SENSOR_VERIFY_TLS=false
INTERNAL_SENSOR_ALLOW_HTTP=true
HOST_AUTH_API_URL=http://host.docker.internal:18088/api/v1/sensors/host-auth
WEB_ACCESS_API_URL=http://host.docker.internal:18088/api/v1/sensors/web-access
EXTERNAL_CONTROL_API_URL=http://host.docker.internal:18090/api/v1/external-sources
EXTERNAL_CONTROL_API_TOKEN=${EXTERNAL_CONTROL_TOKEN}
EXTERNAL_CONTROL_VERIFY_TLS=false
EXTERNAL_CONTROL_ALLOW_HTTP=true
EOF
chown root:ammar /opt/cti-platform/clients/*.env
chmod 0640 /opt/cti-platform/clients/*.env
rm -f /opt/cti-platform/clients/alaa-publisher.env

gateway_ready=false
for _attempt in $(seq 1 30); do
  if curl --fail --silent --show-error http://127.0.0.1:8088/health >/dev/null 2>&1; then
    gateway_ready=true
    break
  fi
  sleep 2
done
if [[ "${gateway_ready}" != "true" ]]; then
  docker compose --env-file "${secret_file}" -f "${vps_dir}/compose.yaml" logs --tail 100 gateway >&2
  exit 1
fi
external_ready=false
for _attempt in $(seq 1 40); do
  if curl --fail --silent --show-error http://127.0.0.1:8090/api/v1/external-sources/health >/dev/null 2>&1; then
    external_ready=true
    break
  fi
  sleep 3
done
if [[ "${external_ready}" != "true" ]]; then
  docker compose --env-file "${secret_file}" -f "${vps_dir}/compose.yaml" logs --tail 100 external-sources >&2
  exit 1
fi
systemctl enable --now cti-external-collection.timer
docker compose --env-file "${secret_file}" -f "${vps_dir}/compose.yaml" ps
systemctl --no-pager --full status \
  cti-ssh-collector.timer cti-docker-firewall.service \
  cti-external-collection.timer cti-storage-maintenance.timer | sed -n '1,56p'
