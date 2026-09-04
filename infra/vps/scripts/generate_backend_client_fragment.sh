#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "generate_backend_client_fragment.sh must run as root" >&2
  exit 1
fi

readonly secret_file="${1:-/etc/cti-platform/vps.env}"
readonly client_dir="${2:-/opt/cti-platform/clients}"
readonly target="${client_dir}/ammar-backend.env"
temporary=""

cleanup() {
  if [[ -n "${temporary}" ]]; then
    rm -f -- "${temporary}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ ! -s "${secret_file}" ]]; then
  echo "VPS secret file is missing or empty" >&2
  exit 1
fi

install -d -o root -g ammar -m 0750 "${client_dir}"
umask 077
temporary=$(mktemp "${client_dir}/.ammar-backend.env.XXXXXX")

set -a
# shellcheck disable=SC1090
source "${secret_file}"
set +a

cat >"${temporary}" <<EOF
# Plain HTTP is approved only for the two isolated Docker aliases below.
EXTERNAL_FEED_URL=http://cti-gateway:8080/api/v1/external-feed
EXTERNAL_FEED_TOKEN=${FEED_READ_TOKEN}
EXTERNAL_FEED_HMAC_SECRET=${FEED_RESPONSE_HMAC_SECRET}
EXTERNAL_FEED_VERIFY_TLS=false
EXTERNAL_FEED_ALLOW_HTTP=true
DIONAEA_API_URL=http://cti-gateway:8080/api/v1/sensors/dionaea
DIONAEA_API_TOKEN=${SENSOR_READ_TOKEN}
DIONAEA_API_HMAC_SECRET=${SENSOR_RESPONSE_HMAC_SECRET}
DIONAEA_API_VERIFY_TLS=false
DIONAEA_API_ALLOW_HTTP=true
INTERNAL_SENSOR_API_TOKEN=${SENSOR_READ_TOKEN}
INTERNAL_SENSOR_API_HMAC_SECRET=${SENSOR_RESPONSE_HMAC_SECRET}
INTERNAL_SENSOR_VERIFY_TLS=false
INTERNAL_SENSOR_ALLOW_HTTP=true
HOST_AUTH_API_URL=http://cti-gateway:8080/api/v1/sensors/host-auth
WEB_ACCESS_API_URL=http://cti-gateway:8080/api/v1/sensors/web-access
EXTERNAL_CONTROL_API_URL=http://cti-external-control:8000/api/v1/external-sources
EXTERNAL_CONTROL_API_TOKEN=${EXTERNAL_CONTROL_TOKEN}
EXTERNAL_CONTROL_VERIFY_TLS=false
EXTERNAL_CONTROL_ALLOW_HTTP=true
EOF

chown root:ammar "${temporary}"
chmod 0640 "${temporary}"
mv -f -- "${temporary}" "${target}"
temporary=""
