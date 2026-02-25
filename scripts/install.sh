#!/usr/bin/env bash
# =============================================================================
# Andromeda CLI — Linux / macOS Installer
#
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/Thunder-BluePhoenix/andromeda-cli/main/scripts/install.sh | bash
#
# Or download and run manually:
#   chmod +x install.sh && ./install.sh
#
# What this does:
#   1. Detects your OS and CPU architecture
#   2. Downloads the correct andromeda binary from GitHub releases
#   3. Installs to /usr/local/bin (or ~/.local/bin if no write permission)
#   4. Makes it executable
# =============================================================================

set -euo pipefail

REPO="Thunder-BluePhoenix/andromeda-cli"

# ─── Colors ───────────────────────────────────────────────────────────────────
C_RESET='\033[0m'
C_CYAN='\033[0;36m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'

ok()   { echo -e "  ${C_GREEN}[+]${C_RESET} $*"; }
warn() { echo -e "  ${C_YELLOW}[!]${C_RESET} $*"; }
err()  { echo -e "  ${C_RED}[x]${C_RESET} $*"; exit 1; }
info() { echo -e "  $*"; }

# ─── Detect OS ────────────────────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    darwin) OS="macos" ;;
    linux)  OS="linux" ;;
    *)      err "Unsupported OS: $OS" ;;
esac

# ─── Detect architecture ──────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)         ARCH="x86_64" ;;
    aarch64|arm64)  ARCH="aarch64" ;;
    armv7l)         ARCH="arm" ;;
    *)              err "Unsupported architecture: $ARCH" ;;
esac

ASSET_NAME="andromeda-${OS}-${ARCH}"

# ─── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "  ${C_CYAN}║  ANDROMEDA CLI — LINUX / macOS INSTALLER                 ║${C_RESET}"
echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
echo ""
info "Platform   :  ${OS} / ${ARCH}"
info "Asset      :  ${ASSET_NAME}"

# ─── Fetch latest release from GitHub ────────────────────────────────────────
echo ""
info "Fetching latest release from GitHub..."

API_URL="https://api.github.com/repos/${REPO}/releases/latest"
RELEASE_JSON=$(curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: Andromeda-CLI-Installer" \
    "$API_URL") || err "Could not reach GitHub API. Check your internet connection."

TAG=$(echo "$RELEASE_JSON" | grep '"tag_name"' \
    | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | head -1)

DOWNLOAD_URL=$(echo "$RELEASE_JSON" \
    | grep -o "\"browser_download_url\":\"https://[^\"]*/${ASSET_NAME}\"" \
    | grep -o 'https://[^"]*')

if [[ -z "$DOWNLOAD_URL" ]]; then
    err "Asset '${ASSET_NAME}' not found in release ${TAG}."
fi

ok "Found       :  ${TAG}  —  ${ASSET_NAME}"

# ─── Choose install directory ─────────────────────────────────────────────────
if [[ -w "/usr/local/bin" ]]; then
    INSTALL_DIR="/usr/local/bin"
elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO=true
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

DEST="${INSTALL_DIR}/andromeda"

# ─── Download ─────────────────────────────────────────────────────────────────
echo ""
info "Downloading to: ${DEST}"

if [[ "${USE_SUDO:-false}" == "true" ]]; then
    TMP=$(mktemp)
    curl -fsSL -o "$TMP" "$DOWNLOAD_URL"
    chmod +x "$TMP"
    sudo mv "$TMP" "$DEST"
else
    curl -fsSL -o "$DEST" "$DOWNLOAD_URL"
    chmod +x "$DEST"
fi

ok "Installed: ${DEST}"

# ─── PATH check ───────────────────────────────────────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo ""
    warn "${INSTALL_DIR} is not in your PATH."
    info "Add this line to your ~/.bashrc or ~/.zshrc:"
    echo ""
    echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
    echo ""
    info "Then reload your shell:  source ~/.bashrc"
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${C_GREEN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "  ${C_GREEN}║  ANDROMEDA CLI INSTALLED                                 ║${C_RESET}"
echo -e "  ${C_GREEN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
echo ""
echo -e "    ${C_CYAN}andromeda setup   ${C_RESET}  — first-time setup wizard"
echo -e "    ${C_CYAN}andromeda install ${C_RESET}  — download the dashboard binary"
echo -e "    ${C_CYAN}andromeda start   ${C_RESET}  — start the dashboard"
echo -e "    ${C_CYAN}andromeda --help  ${C_RESET}  — show all commands"
echo ""
