#!/usr/bin/env bash
set -euo pipefail

# Cerberus one-liner installer (supports server & zero-setup client modes!)
#
# Install binary only:
#   curl -fsSL https://raw.githubusercontent.com/Baba01hacker666/Cerberus/main/scripts/install.sh | sudo bash
#
# Install & start Main Smart Server on port 7443:
#   curl -fsSL https://raw.githubusercontent.com/Baba01hacker666/Cerberus/main/scripts/install.sh | sudo bash -s -- --server --port 7443
#
# Install & join a Main Server with zero client setup:
#   curl -fsSL https://raw.githubusercontent.com/Baba01hacker666/Cerberus/main/scripts/install.sh | sudo bash -s -- --client 203.0.113.10:7443

REPO="Baba01hacker666/Cerberus"
BIN="cerberus"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/cerberus}"
DATA_DIR="${DATA_DIR:-/var/lib/cerberus}"

MODE=""
PORT="7443"
SERVER_ADDR=""
TOKEN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --server)
      MODE="server"
      shift
      ;;
    --client)
      MODE="client"
      SERVER_ADDR="${2:-}"
      shift 2
      ;;
    --port)
      PORT="${2:-7443}"
      shift 2
      ;;
    --token)
      TOKEN="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

echo "==> Installing Cerberus (${OS}/${ARCH})"

TAG="${CERBERUS_VERSION:-}"
if [ -z "$TAG" ]; then
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1 || true)"
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
  echo "==> Building from source (requires Go >= 1.24)"
  if ! command -v go >/dev/null 2>&1; then
    echo "Go not found; install Go first: https://go.dev/dl/" >&2
    exit 1
  fi
  git clone --depth 1 "https://github.com/${REPO}.git" "${TMPDIR}/src"
  (cd "${TMPDIR}/src" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${TMPDIR}/${BIN}" .)
  chmod +x "${TMPDIR}/${BIN}"
fi

echo "==> Installing binary to ${INSTALL_DIR}/${BIN}"
install -m 0755 "${TMPDIR}/${BIN}" "${INSTALL_DIR}/${BIN}"
mkdir -p "$CONFIG_DIR" "$DATA_DIR"

if command -v systemctl >/dev/null 2>&1; then
  TOKEN_ARG=""
  if [ -n "$TOKEN" ]; then
    TOKEN_ARG="--token ${TOKEN}"
  fi
  if [ "$MODE" = "client" ] && [ -n "$SERVER_ADDR" ]; then
    EXEC_CMD="${INSTALL_DIR}/${BIN} --config ${CONFIG_DIR}/config.yaml client ${SERVER_ADDR} ${TOKEN_ARG}"
  else
    EXEC_CMD="${INSTALL_DIR}/${BIN} --config ${CONFIG_DIR}/config.yaml server --port ${PORT} ${TOKEN_ARG}"
  fi

  cat > /etc/systemd/system/cerberus.service <<UNIT
[Unit]
Description=Cerberus WireGuard Smart Mesh Service
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${EXEC_CMD}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  if [ -n "$MODE" ]; then
    systemctl enable --now cerberus
    echo "==> Service started! Check status with: systemctl status cerberus"
  else
    echo "==> Enable with: systemctl enable --now cerberus"
  fi
fi

echo "==> Done! Quick start:"
echo "    Main Server: sudo cerberus server --port ${PORT}"
echo "    Any Client:  sudo cerberus client <SERVER_IP>:${PORT}"
