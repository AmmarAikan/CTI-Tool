#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "deploy_misp.sh must run as root" >&2
  exit 1
fi

release_root="${1:-/opt/cti-platform/current}"
override_file="${release_root}/infra/vps/misp/compose.override.yaml"
ipv4_sysctl_file="${release_root}/infra/vps/sysctl/99-cti-ipv4-only.conf"
misp_root=/opt/misp-docker
misp_commit=223b675c4480730832f928e113b6f2e5260b450d

if [[ ! -f "${override_file}" ]]; then
  echo "Missing MISP override: ${override_file}" >&2
  exit 1
fi
if [[ ! -f "${ipv4_sysctl_file}" ]]; then
  echo "Missing CTI IPv4 sysctl policy: ${ipv4_sysctl_file}" >&2
  exit 1
fi

"${release_root}/infra/vps/scripts/provision_backend_networks.sh"

# This VPS has reproducibly reset large GHCR downloads over IPv6.  Keep the
# host on the tested IPv4 path; all public CTI services and SSH tunnels use IPv4.
install -o root -g root -m 0644 "${ipv4_sysctl_file}" /etc/sysctl.d/99-cti-ipv4-only.conf
sysctl --system >/dev/null

if [[ ! -d "${misp_root}/.git" ]]; then
  git clone https://github.com/MISP/misp-docker.git "${misp_root}"
fi
git -C "${misp_root}" fetch --depth 1 origin "${misp_commit}"
git -C "${misp_root}" checkout --detach "${misp_commit}"

install -d -m 0750 /etc/cti-platform
misp_env=/etc/cti-platform/misp.env
if [[ ! -s "${misp_env}" ]]; then
  umask 077
  cp "${misp_root}/template.env" "${misp_env}"
  cat >> "${misp_env}" <<EOF

# CTI lab overrides.  Images are pulled by versioned slim tags, never latest.
CORE_RUNNING_TAG=v2.5.44-slim
MODULES_RUNNING_TAG=v3.0.9-slim
BASE_URL=https://localhost:18443
CORE_HTTP_PORT=127.0.0.1:8080
CORE_HTTPS_PORT=127.0.0.1:8443
ADMIN_EMAIL=admin@cti.local
ADMIN_ORG=Graduation-CTI-Lab
ADMIN_PASSWORD=$(openssl rand -hex 24)
ADMIN_KEY=$(openssl rand -hex 20)
GPG_PASSPHRASE=$(openssl rand -hex 24)
MYSQL_USER=misp
MYSQL_DATABASE=misp
MYSQL_PASSWORD=$(openssl rand -hex 32)
MYSQL_ROOT_PASSWORD=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -hex 16)
SALT=$(openssl rand -hex 32)
UUID=$(cat /proc/sys/kernel/random/uuid)
DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true
DISABLE_IPV6=true
ENABLE_DB_SETTINGS=true
ENABLE_BACKGROUND_UPDATES=false
INNODB_BUFFER_POOL_SIZE=512M
INNODB_LOG_FILE_SIZE=128M
INNODB_READ_IO_THREADS=4
INNODB_WRITE_IO_THREADS=4
PHP_MEMORY_LIMIT=1024M
PHP_FCGI_CHILDREN=3
PHP_FCGI_START_SERVERS=1
PHP_FCGI_SPARE_SERVERS=1
TZ=UTC
EOF
fi
chmod 0600 "${misp_env}"

compose=(docker compose --env-file "${misp_env}" -f "${misp_root}/docker-compose.yml" -f "${override_file}")
images_ready=false
for _attempt in $(seq 1 3); do
  if "${compose[@]}" pull redis db misp-modules misp-core; then
    images_ready=true
    break
  fi
  sleep 10
done
if [[ "${images_ready}" != "true" ]]; then
  echo "MISP images could not be pulled after three attempts" >&2
  exit 1
fi
"${compose[@]}" up -d --no-build redis db misp-modules misp-core

misp_ready=false
for _attempt in $(seq 1 90); do
  if curl --insecure --fail --silent https://127.0.0.1:8443/users/heartbeat >/dev/null 2>&1; then
    misp_ready=true
    break
  fi
  sleep 10
done
if [[ "${misp_ready}" != "true" ]]; then
  "${compose[@]}" ps >&2
  "${compose[@]}" logs --tail 120 misp-core >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${misp_env}"
set +a
install -d -o root -g root -m 0700 /opt/cti-platform/clients
umask 027
cat > /opt/cti-platform/clients/misp-client.env <<EOF
MISP_URL=http://cti-misp
MISP_API_KEY=${ADMIN_KEY}
MISP_VERIFY_TLS=true
MISP_ALLOW_HTTP=true
EOF
chown root:root /opt/cti-platform/clients/misp-client.env
chmod 0600 /opt/cti-platform/clients/misp-client.env
"${compose[@]}" ps
