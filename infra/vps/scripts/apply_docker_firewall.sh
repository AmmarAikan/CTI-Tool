#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "apply_docker_firewall.sh must run as root" >&2
  exit 1
fi

# Docker-published ports do not follow ordinary UFW forwarding policy.  These
# DOCKER-USER rules allow replies to inbound connections, but prevent a
# compromised sensor or gateway from starting a new connection to the Internet.
for subnet in 172.30.10.0/24 172.30.20.0/24; do
  if ! iptables -C DOCKER-USER -s "${subnet}" -j DROP 2>/dev/null; then
    iptables -I DOCKER-USER 1 -s "${subnet}" -j DROP
  fi
  if ! iptables -C DOCKER-USER -s "${subnet}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -s "${subnet}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi
done
