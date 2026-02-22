#!/bin/bash
set -euo pipefail

# Upload creddy binary to exe.dev test machines
# Usage: ./scripts/test/exe-dev.sh <server|client>

BINARY="creddy"
BUILD_DIR="bin"
LINUX_BINARY="${BUILD_DIR}/${BINARY}-linux-amd64"
REMOTE_PATH="/usr/local/bin/${BINARY}"

case "${1:-}" in
    server)
        HOST="creddy-server.exe.xyz"
        ;;
    client)
        HOST="creddy-client.exe.xyz"
        ;;
    *)
        echo "Usage: $0 <server|client>"
        exit 1
        ;;
esac

if [[ ! -f "${LINUX_BINARY}" ]]; then
    echo "Binary not found. Run 'make build-linux' first."
    exit 1
fi

echo "Uploading to ${HOST}..."
scp "${LINUX_BINARY}" "${HOST}:/tmp/${BINARY}"
ssh "${HOST}" "sudo mv /tmp/${BINARY} ${REMOTE_PATH} && sudo chmod +x ${REMOTE_PATH}"
echo "✅ Done"
