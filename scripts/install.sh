#!/bin/sh
# Creddy installer script
# Usage: curl -fsSL https://get.creddy.dev/install.sh | sh
#        curl -fsSL https://get.creddy.dev/install.sh | sh -s -- v0.1.0
#
# Environment variables:
#   INSTALL_DIR    - Override install directory
#   SKIP_VERIFY    - Skip checksum verification (not recommended)

set -e

REPO_URL="https://get.creddy.dev/cli"
BINARY_NAME="creddy"

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

info() {
    printf "${BLUE}==>${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}==>${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}Warning:${NC} %s\n" "$1"
}

error() {
    printf "${RED}Error:${NC} %s\n" "$1" >&2
    exit 1
}

# Detect OS
detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        linux*)  OS="linux" ;;
        darwin*) OS="darwin" ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *)       error "Unsupported operating system: $OS" ;;
    esac
    echo "$OS"
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)             error "Unsupported architecture: $ARCH" ;;
    esac
    echo "$ARCH"
}

# Check if we can use sudo
can_sudo() {
    # Check if sudo exists and we can use it
    if ! has_cmd sudo; then
        return 1
    fi
    # Check if we're in a terminal (can prompt for password)
    if [ ! -t 0 ]; then
        # Not a terminal, check if sudo is passwordless
        sudo -n true 2>/dev/null
        return $?
    fi
    return 0
}

# Determine install directory
get_install_dir() {
    if [ -n "$INSTALL_DIR" ]; then
        echo "$INSTALL_DIR"
        return
    fi
    
    # Already root
    if [ "$(id -u)" = "0" ]; then
        echo "/usr/local/bin"
        return
    fi
    
    # /usr/local/bin is writable
    if [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
        return
    fi
    
    # Can we use sudo?
    if can_sudo; then
        echo "/usr/local/bin"
        return
    fi
    
    # Fall back to ~/.local/bin
    echo "$HOME/.local/bin"
}

# Check if command exists
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Download file
download() {
    URL="$1"
    OUTPUT="$2"
    
    if has_cmd curl; then
        curl -fsSL "$URL" -o "$OUTPUT"
    elif has_cmd wget; then
        wget -q "$URL" -O "$OUTPUT"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
}

# Verify SHA256 checksum
verify_checksum() {
    FILE="$1"
    EXPECTED="$2"
    
    if [ -n "$SKIP_VERIFY" ]; then
        warn "Skipping checksum verification (SKIP_VERIFY is set)"
        return 0
    fi
    
    if has_cmd sha256sum; then
        ACTUAL=$(sha256sum "$FILE" | awk '{print $1}')
    elif has_cmd shasum; then
        ACTUAL=$(shasum -a 256 "$FILE" | awk '{print $1}')
    else
        warn "Neither sha256sum nor shasum found. Skipping checksum verification."
        return 0
    fi
    
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        error "Checksum verification failed!\n  Expected: $EXPECTED\n  Got:      $ACTUAL"
    fi
}

# Add directory to PATH in shell config
add_to_path() {
    DIR="$1"
    
    # Check if already in PATH
    case ":$PATH:" in
        *":$DIR:"*) return 0 ;;
    esac
    
    SHELL_NAME=$(basename "$SHELL")
    case "$SHELL_NAME" in
        bash)
            RC_FILE="$HOME/.bashrc"
            ;;
        zsh)
            RC_FILE="$HOME/.zshrc"
            ;;
        *)
            warn "Unknown shell: $SHELL_NAME. Please add $DIR to your PATH manually."
            return 0
            ;;
    esac
    
    if [ -f "$RC_FILE" ]; then
        if ! grep -q ".local/bin" "$RC_FILE" 2>/dev/null; then
            echo "" >> "$RC_FILE"
            echo "# Added by Creddy installer" >> "$RC_FILE"
            echo "export PATH=\"$DIR:\$PATH\"" >> "$RC_FILE"
            info "Added $DIR to PATH in $RC_FILE"
            info "Run 'source $RC_FILE' or restart your shell to use creddy"
        fi
    fi
}

main() {
    VERSION="${1:-latest}"
    
    info "Installing Creddy..."
    
    OS=$(detect_os)
    ARCH=$(detect_arch)
    INSTALL_DIR=$(get_install_dir)
    
    info "Detected: $OS/$ARCH"
    info "Install directory: $INSTALL_DIR"
    
    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf '$TMP_DIR'" EXIT
    
    # Fetch manifest
    info "Fetching manifest..."
    MANIFEST_URL="$REPO_URL/$VERSION/manifest.json"
    download "$MANIFEST_URL" "$TMP_DIR/manifest.json" || error "Failed to download manifest. Is '$VERSION' a valid version?"
    
    # Parse manifest for our platform (simple grep/sed, no jq dependency)
    # Find the binary entry for our OS/arch
    BINARY_INFO=$(cat "$TMP_DIR/manifest.json" | tr -d '\n' | grep -o "{[^}]*\"os\": *\"$OS\"[^}]*\"arch\": *\"$ARCH\"[^}]*}" || true)
    
    if [ -z "$BINARY_INFO" ]; then
        error "No binary found for $OS/$ARCH in version $VERSION"
    fi
    
    # Extract URL and checksum
    DOWNLOAD_URL=$(echo "$BINARY_INFO" | grep -o '"url": *"[^"]*"' | sed 's/"url": *"\([^"]*\)"/\1/')
    CHECKSUM=$(echo "$BINARY_INFO" | grep -o '"sha256": *"[^"]*"' | sed 's/"sha256": *"\([^"]*\)"/\1/')
    FILENAME=$(echo "$BINARY_INFO" | grep -o '"filename": *"[^"]*"' | sed 's/"filename": *"\([^"]*\)"/\1/')
    
    if [ -z "$DOWNLOAD_URL" ]; then
        error "Could not parse download URL from manifest"
    fi
    
    # Download binary
    info "Downloading $FILENAME..."
    download "$DOWNLOAD_URL" "$TMP_DIR/$FILENAME"
    
    # Verify checksum
    info "Verifying checksum..."
    verify_checksum "$TMP_DIR/$FILENAME" "$CHECKSUM"
    success "Checksum verified"
    
    # Create install directory if needed
    if [ ! -d "$INSTALL_DIR" ]; then
        mkdir -p "$INSTALL_DIR"
    fi
    
    # Install binary
    DEST="$INSTALL_DIR/$BINARY_NAME"
    if [ "$INSTALL_DIR" = "/usr/local/bin" ] && [ "$(id -u)" != "0" ]; then
        info "Installing to $DEST (requires sudo)..."
        sudo mv "$TMP_DIR/$FILENAME" "$DEST"
        sudo chmod +x "$DEST"
    else
        mv "$TMP_DIR/$FILENAME" "$DEST"
        chmod +x "$DEST"
    fi
    
    # Add to PATH if needed
    if [ "$INSTALL_DIR" = "$HOME/.local/bin" ]; then
        add_to_path "$INSTALL_DIR"
    fi
    
    success "Creddy installed successfully!"
    echo ""
    
    # Print version
    if has_cmd "$DEST"; then
        echo "  Version: $($DEST version 2>/dev/null || echo "unknown")"
    fi
    echo "  Location: $DEST"
    echo ""
    
    # Warn about sudo PATH if installed to ~/.local/bin
    if [ "$INSTALL_DIR" = "$HOME/.local/bin" ]; then
        warn "Installed to $INSTALL_DIR (sudo won't find it)"
        echo "  For 'sudo creddy install', use: sudo $DEST install"
        echo "  Or reinstall with: sudo sh -c 'curl -fsSL https://get.creddy.dev/install.sh | sh'"
        echo ""
    fi
    
    echo "Get started:"
    echo "  creddy --help"
    echo ""
}

main "$@"
