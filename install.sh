#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root (use sudo)." >&2
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

pkg_install() {
  local pkg="$1"
  if need_cmd apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
    return 0
  fi
  if need_cmd dnf; then
    dnf install -y "$pkg"
    return 0
  fi
  if need_cmd yum; then
    yum install -y "$pkg"
    return 0
  fi
  if need_cmd pacman; then
    pacman -Sy --noconfirm "$pkg"
    return 0
  fi
  echo "No supported package manager found to install: $pkg" >&2
  return 1
}

ensure_deps() {
  if ! need_cmd curl; then
    pkg_install curl
  fi
  if ! need_cmd git; then
    pkg_install git
  fi
  if ! need_cmd go; then
    pkg_install golang || pkg_install golang-go
  fi
}

ensure_ufw() {
  if ! need_cmd ufw; then
    pkg_install ufw
  fi

  if ! ufw status >/dev/null 2>&1; then
    echo "ufw exists but is not usable. Are you running on a UFW-supported distro?" >&2
    exit 1
  fi

  if ufw status 2>/dev/null | head -n 1 | grep -qi "inactive"; then
    ufw --force enable >/dev/null
  fi
}

build_and_install() {
  local repo="https://github.com/ifernandosousa/ufw2me.git"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  git clone --depth 1 "$repo" "$tmp" >/dev/null
  (cd "$tmp" && go build -trimpath -ldflags "-s -w" -o /usr/local/bin/ufw2me .)
  chmod 0755 /usr/local/bin/ufw2me
}

ensure_config() {
  if [[ ! -f /etc/ufw2me.env ]]; then
    cat > /etc/ufw2me.env <<'EOF'
UFW2ME_PORT=9850
EOF
    chmod 0644 /etc/ufw2me.env
  fi
}

ensure_systemd_service() {
  if ! need_cmd systemctl; then
    echo "systemd not detected; install completed, but service was not configured." >&2
    echo "Run: UFW2ME_PORT=9850 /usr/local/bin/ufw2me" >&2
    exit 0
  fi

  cat > /etc/systemd/system/ufw2me.service <<'EOF'
[Unit]
Description=ufw2me - Web UI for UFW
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/ufw2me.env
ExecStart=/usr/local/bin/ufw2me
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now ufw2me.service
}

ensure_deps
ensure_ufw
build_and_install
ensure_config
ensure_systemd_service

port="$(grep -E '^UFW2ME_PORT=' /etc/ufw2me.env 2>/dev/null | tail -n 1 | cut -d= -f2 || true)"
port="${port:-9850}"
echo "ufw2me installed and running on port ${port}."
