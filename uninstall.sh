#!/usr/bin/env bash
# =============================================================================
#  ML-Enhanced Honeypot — Linux & macOS Uninstaller
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }

OS="$(uname -s)"
INSTALL_DIR_LINUX="/opt/honeypot"
INSTALL_DIR_MACOS="$HOME/honeypot"

echo ""
echo -e "${RED}${BOLD}ML-Enhanced Honeypot — Uninstaller${RESET}"
echo ""

if [[ "$OS" == "Linux" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${RESET} Run as root: sudo bash uninstall.sh"; exit 1
    fi
    INSTALL_DIR="$INSTALL_DIR_LINUX"

    # Stop and disable systemd services
    for svc in honeypot honeypot-dashboard; do
        if systemctl list-units --full --all | grep -q "${svc}.service"; then
            systemctl stop    "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            ok "Service $svc stopped and disabled."
        fi
        if [[ -f "/etc/systemd/system/${svc}.service" ]]; then
            rm -f "/etc/systemd/system/${svc}.service"
            ok "Removed /etc/systemd/system/${svc}.service"
        fi
    done
    systemctl daemon-reload

elif [[ "$OS" == "Darwin" ]]; then
    INSTALL_DIR="$INSTALL_DIR_MACOS"
    LAUNCHD_DIR="$HOME/Library/LaunchAgents"

    for plist in com.honeypot com.honeypot.dashboard; do
        if [[ -f "$LAUNCHD_DIR/${plist}.plist" ]]; then
            launchctl unload "$LAUNCHD_DIR/${plist}.plist" 2>/dev/null || true
            rm -f "$LAUNCHD_DIR/${plist}.plist"
            ok "Removed launchd agent: $plist"
        fi
    done
else
    warn "Unknown OS '$OS'. Manual cleanup may be needed."
    INSTALL_DIR="$INSTALL_DIR_LINUX"
fi

# Remove install directory
if [[ -d "$INSTALL_DIR" ]]; then
    read -r -p "Remove installation directory $INSTALL_DIR? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
        ok "Removed $INSTALL_DIR"
    else
        warn "Skipped removal of $INSTALL_DIR"
    fi
fi

echo ""
echo -e "${GREEN}${BOLD}Uninstall complete.${RESET}"
echo ""
