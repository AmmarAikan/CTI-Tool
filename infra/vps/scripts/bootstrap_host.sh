#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "bootstrap_host.sh must run as root" >&2
  exit 1
fi

source /etc/os-release
if [[ "${ID}" != "ubuntu" || "${VERSION_ID}" != "24.04" ]]; then
  echo "This reviewed bootstrap targets Ubuntu 24.04 only" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl fail2ban gnupg logrotate ufw unattended-upgrades

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

install -d -m 0755 /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
systemctl enable --now docker

if ! swapon --show=NAME --noheadings | grep -q .; then
  if [[ ! -e /swapfile ]]; then
    fallocate -l 4G /swapfile
    chmod 0600 /swapfile
    mkswap /swapfile
  fi
  swapon /swapfile
fi
if ! grep -qE '^/swapfile[[:space:]]' /etc/fstab; then
  printf '%s\n' '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# OpenSSH uses the first value it reads for most global options.  Cloud images
# commonly ship 50-cloud-init.conf with PasswordAuthentication=yes, so this
# project policy must sort before cloud-init rather than after it.
rm -f /etc/ssh/sshd_config.d/99-cti-hardening.conf
cat > /etc/ssh/sshd_config.d/00-cti-hardening.conf <<'EOF'
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding yes
PermitTunnel no
EOF
sshd -t
systemctl reload ssh

cat > /etc/fail2ban/jail.d/cti-sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
port = 22
maxretry = 5
findtime = 10m
bantime = 1h
EOF
systemctl enable --now fail2ban

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH key administration'
ufw allow 21/tcp comment 'Dionaea FTP honeypot'
ufw allow 445/tcp comment 'Dionaea SMB honeypot'
ufw allow 1433/tcp comment 'Dionaea MSSQL honeypot'
ufw allow 3306/tcp comment 'Dionaea MySQL honeypot'
ufw allow 5060/tcp comment 'Dionaea SIP honeypot'
ufw allow 5060/udp comment 'Dionaea SIP honeypot'
ufw allow 11211/tcp comment 'Dionaea Memcached honeypot'
ufw --force enable

systemctl enable unattended-upgrades
systemctl start unattended-upgrades || true

docker --version
docker compose version
ufw status verbose
swapon --show
fail2ban-client status sshd
