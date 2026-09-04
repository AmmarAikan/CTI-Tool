#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "provision_backend_networks.sh must run as root" >&2
  exit 1
fi

readonly -a NETWORKS=(cti-backend-gateway cti-backend-external)

die() {
  echo "$1" >&2
  exit 1
}

validate_membership() {
  local network_name=$1 allowed_a=$2 allowed_b=$3
  local ids id service
  declare -A seen=()

  if ! ids=$(docker network inspect --format '{{range $id, $_ := .Containers}}{{$id}}{{"\n"}}{{end}}' "${network_name}"); then
    die "Unable to inspect existing network ${network_name}"
  fi
  while IFS= read -r id; do
    [[ -z "${id}" ]] && continue
    if ! service=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "${id}"); then
      die "Unable to inspect a container attached to ${network_name}"
    fi
    if [[ "${service}" != "${allowed_a}" && "${service}" != "${allowed_b}" ]]; then
      die "Network ${network_name} has an unauthorized attached container"
    fi
    if [[ -n "${seen[${service}]:-}" ]]; then
      die "Network ${network_name} has more than one ${service} container"
    fi
    seen[${service}]=1
  done <<<"${ids}"
}

ensure_network() {
  local network_name=$1 allowed_a=$2 allowed_b=$3
  local listed driver internal

  if ! listed=$(docker network ls --filter "name=^${network_name}$" --format '{{.Name}}'); then
    die "Unable to list Docker networks"
  fi
  if [[ -z "${listed}" ]]; then
    if ! docker network create --driver bridge --internal "${network_name}" >/dev/null; then
      die "Unable to create network ${network_name}"
    fi
  elif [[ "${listed}" != "${network_name}" ]]; then
    die "Docker returned an ambiguous match for ${network_name}"
  fi

  if ! driver=$(docker network inspect --format '{{.Driver}}' "${network_name}"); then
    die "Unable to inspect driver for ${network_name}"
  fi
  if ! internal=$(docker network inspect --format '{{.Internal}}' "${network_name}"); then
    die "Unable to inspect internal mode for ${network_name}"
  fi
  if [[ "${driver}" != "bridge" || "${internal}" != "true" ]]; then
    die "Existing network ${network_name} must be an internal bridge"
  fi
  validate_membership "${network_name}" "${allowed_a}" "${allowed_b}"
}

ensure_network cti-backend-gateway backend gateway
ensure_network cti-backend-external backend external-sources
