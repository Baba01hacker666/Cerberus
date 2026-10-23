#!/usr/bin/env bash
set -euo pipefail

# Cerberus one-liner installer
# Usage: curl -fsSL https://raw.githubusercontent.com/baba01hacker/cerberus/main/scripts/install.sh | bash

REPO="baba01hacker/cerberus"
BIN="cerberus"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/cerberus}"
DATA_DIR="${DATA_DIR:-/var/lib/cerberus}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

echo "==> Installing Cerberus (${OS}/${ARCH})"

# Determine latest release tag
TAG="${CERBERUS_VERSION:-}"
if [ -z "$TAG" ]; then
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [ -n "$TAG" ]; then
  URL="https://github.com/${REPO}/releases/download/${TAG}/${BIN}-${OS}-${ARCH}"
  echo "==> Downloading ${URL}"
  if curl -fsSL "$URL" -o "${TMPDIR}/${BIN}"; then
    chmod +x "${TMPDIR}/${BIN}"
  else
    echo "==> release binary not found, building from source"
    TAG=""
  fi
fi

if [ -z "$TAG" ]; then
  echo "==> Building from source (requires Go >= 1.22)"
  if ! command -v go >/dev/null 2>&1; then
    echo "Go not found; install Go first: https://go.dev/dl/" >&2
    exit 1
  fi
  git clone --depth 1 "https://github.com/${REPO}.git" "${TMPDIR}/src"
  (cd "${TMPDIR}/src" && go build -o "${TMPDIR}/${BIN}" .)
  chmod +x "${TMPDIR}/${BIN}"
fi

echo "==> Installing binary to ${INSTALL_DIR}/${BIN}"
install -m 0755 "${TMPDIR}/${BIN}" "${INSTALL_DIR}/${BIN}"

echo "==> Creating directories"
mkdir -p "$CONFIG_DIR" "$DATA_DIR"

if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
  "${INSTALL_DIR}/${BIN}" init --config "${CONFIG_DIR}/config.yaml" || true
fi

# systemd service (optional)
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/cerberus.service <<UNIT
[Unit]
Description=Cerberus mesh daemon
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BIN} daemon --config ${CONFIG_DIR}/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  echo "==> Enable with: systemctl enable --now cerberus"
fi

echo "==> Done. Run: cerberus version"
