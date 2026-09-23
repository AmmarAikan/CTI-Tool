#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="actit-defense-demo"
COMPOSE_FILE="compose.demo.yml"
DEMO_PORT="${ACTIT_DEMO_PORT:-19090}"
DEMO_URL="http://127.0.0.1:${DEMO_PORT}"

compose() {
  docker compose --project-name "${PROJECT_NAME}" --file "${COMPOSE_FILE}" "$@"
}

preflight() {
  test "$(git branch --show-current)" = "codex/actit-final-production" || {
    echo "Refusing to run outside codex/actit-final-production" >&2
    return 1
  }
  for path in "${COMPOSE_FILE}" scripts/create_demo_dataset.py scripts/defense_demo_provider.py tests/fixtures/defense_demo/web_access.jsonl; do
    test -f "${path}" || { echo "Missing ${path}" >&2; return 1; }
  done
  docker info >/dev/null
  docker compose version >/dev/null
  compose config --quiet
  if ss -Hln "sport = :${DEMO_PORT}" | rg -q . && ! compose ps --status running --quiet frontend | rg -q .; then
    echo "Loopback port ${DEMO_PORT} is already in use by another process" >&2
    return 1
  fi
  if compose config | rg -q '/opt/cti-platform|external: true|cti_postgres_data|cti-backend-gateway'; then
    echo "Rendered demo topology references a forbidden production resource" >&2
    return 1
  fi
  echo "Preflight passed: isolated project ${PROJECT_NAME}, loopback URL ${DEMO_URL}"
}

wait_for_frontend() {
  local attempt
  for attempt in $(seq 1 90); do
    if curl --fail --silent --show-error "${DEMO_URL}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  compose ps
  return 1
}

set_review_mode() {
  local mode="${1:?review mode is required}"
  case "${mode}" in available|empty) ;; *) echo "Mode must be available or empty" >&2; return 2 ;; esac
  compose exec --no-TTY demo-provider python -c "import urllib.request; request=urllib.request.Request('http://127.0.0.1:8081/demo/reviews/mode/${mode}', method='POST', headers={'X-Demo-Control':'defense-demo-control'}); urllib.request.urlopen(request, timeout=5).read()"
  echo "Reviews demo state: ${mode}"
}

case "${1:-}" in
  preflight)
    preflight
    ;;
  prepare)
    preflight
    compose pull demo-db
    compose --profile validation build demo-gateway backend frontend demo-smoke
    echo "Demo images prepared from the current worktree. Core startup can now run without Internet access."
    ;;
  start)
    preflight
    compose up --detach --wait
    wait_for_frontend
    set_review_mode available
    echo "ACTIT defense demo is ready at ${DEMO_URL}"
    ;;
  start-build)
    preflight
    compose up --detach --build --wait
    wait_for_frontend
    set_review_mode available
    echo "ACTIT defense demo is ready at ${DEMO_URL}"
    ;;
  smoke)
    preflight
    wait_for_frontend
    set_review_mode available
    compose --profile validation run --rm --no-deps demo-smoke python scripts/defense_demo_smoke.py --base-url http://frontend:8080 --reviews-mode available
    set_review_mode empty
    compose --profile validation run --rm --no-deps demo-smoke python scripts/defense_demo_smoke.py --base-url http://frontend:8080 --reviews-mode empty
    set_review_mode available
    ;;
  reviews)
    set_review_mode "${2:-}"
    ;;
  status)
    compose ps
    ;;
  stop)
    compose down --volumes --remove-orphans
    echo "Removed only the ${PROJECT_NAME} containers, network, and disposable volume."
    ;;
  *)
    echo "Usage: $0 {preflight|prepare|start|start-build|smoke|reviews available|reviews empty|status|stop}" >&2
    exit 2
    ;;
esac
