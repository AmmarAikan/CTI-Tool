#!/usr/bin/env bash
set -euo pipefail

readonly PROJECT="cti-ext-readiness"
readonly COMPOSE_FILE="compose.external-test.yml"
readonly ENV_FILE=".env.external-test"

fail() { printf 'readiness=blocked category=%s\n' "$1"; exit 1; }
pass() { printf 'check=%s status=ready\n' "$1"; }

[[ "${COMPOSE_PROJECT_NAME:-$PROJECT}" == "$PROJECT" ]] || fail wrong_compose_project
[[ -f "$COMPOSE_FILE" && -f "$ENV_FILE" ]] || fail isolated_configuration_missing
for path in config/dark_web_sources.external-test.json config/dark_web_discovery_providers.external-test.json; do
  [[ -f "$path" && ! -L "$path" ]] || fail protected_configuration_missing
  mode="$(stat -c '%a' "$path")"
  [[ "$mode" == "600" || "$mode" == "640" || "$mode" == "644" ]] || fail protected_configuration_permissions
done
docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --quiet || fail compose_invalid
for service in tor external-sources backend frontend db; do
  count="$(docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps -q "$service" | wc -l)"
  [[ "$count" == "1" ]] || fail duplicate_or_missing_container
done
tor_id="$(docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps -q tor)"
[[ "$(docker inspect -f '{{.State.Health.Status}}' "$tor_id")" == "healthy" ]] || fail tor_unhealthy
[[ "$(docker port "$tor_id" 2>/dev/null)" == "" ]] || fail tor_port_published
docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" exec -T external-sources \
  python -c "import os,socket; assert os.environ.get('TOR_PROXY_HOST')=='tor'; assert os.environ.get('TOR_PROXY_PORT')=='9050'; socket.create_connection(('tor',9050),3).close()" \
  >/dev/null || fail external_to_tor_unavailable
for service in external-sources backend; do
  id="$(docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps -q "$service")"
  [[ "$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || printf none)" == "healthy" ]] || fail service_unhealthy
done
curl --fail --silent --show-error --max-time 3 http://127.0.0.1:19080/ >/dev/null || fail frontend_unhealthy
available_kb="$(df -Pk . | awk 'NR==2 {print $4}')"; [[ "$available_kb" -ge 1048576 ]] || fail disk_low
available_mem_kb="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"; [[ "$available_mem_kb" -ge 524288 ]] || fail memory_low
pass isolated_compose
pass tor_internal_transport
pass protected_configuration
pass application_health
printf 'readiness=ready live_requests=not_performed\n'
