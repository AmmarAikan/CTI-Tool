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
EXTERNAL_FEED_ID=external-team-feed
SENSOR_ID=cti-vps
SENSOR_READ_GID=31002
MAX_PUBLISH_BYTES=20971520
MAX_SENSOR_BYTES=52428800
MAX_FEED_ITEMS=20000
EOF
fi
chmod 0600 "${secret_file}"

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
install -o root -g root -m 0644 "${vps_dir}/systemd/cti-docker-firewall.service" /etc/systemd/system/cti-docker-firewall.service

systemctl daemon-reload
systemctl enable --now cti-ssh-collector.timer
systemctl start cti-ssh-collector.service

docker compose --env-file "${secret_file}" -f "${vps_dir}/compose.yaml" build
docker compose --env-file "${secret_file}" -f "${vps_dir}/compose.yaml" up -d
systemctl enable --now cti-docker-firewall.service

# Produce least-privilege client fragments without exposing values in command output.
# The Ammar fragment reads feeds/sensors; the Alaa fragment can only publish a feed.
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
EOF
cat > /opt/cti-platform/clients/alaa-publisher.env <<EOF
EXTERNAL_FEED_PUBLISH_URL=http://127.0.0.1:18088/api/v1/external-feed/publish
EXTERNAL_FEED_PUBLISH_TOKEN=${FEED_PUBLISH_TOKEN}
EOF
chown root:ammar /opt/cti-platform/clients/*.env
chmod 0640 /opt/cti-platform/clients/*.env

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
docker compose --env-file "${secret_file}" -f "${vps_dir}/compose.yaml" ps
systemctl --no-pager --full status cti-ssh-collector.timer cti-docker-firewall.service | sed -n '1,28p'
