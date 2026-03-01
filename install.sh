#!/usr/bin/env bash
# =============================================================================
#  ML-Enhanced Honeypot — Linux & macOS Installer
#  Supports: Ubuntu/Debian  |  macOS (Homebrew)
#
#  Usage:
#    sudo bash install.sh          # installs system-wide as a service
#    bash install.sh --no-service  # installs deps only, no service
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
step()  { echo -e "\n${BOLD}── $* ──${RESET}"; }

# ── Config ────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/honeypot"
SERVICE_NAME="honeypot"
DASHBOARD_SERVICE_NAME="honeypot-dashboard"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"
NO_SERVICE=false
OS="$(uname -s)"

for arg in "$@"; do
  [[ "$arg" == "--no-service" ]] && NO_SERVICE=true
done

# ── Root check (Linux only — macOS uses launchd per-user) ─────────────────────
if [[ "$OS" == "Linux" ]] && [[ $EUID -ne 0 ]] && [[ "$NO_SERVICE" == false ]]; then
  error "Run as root to install as a service: sudo bash install.sh\n       Or use --no-service for a local install."
fi

echo ""
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}${BOLD}║    ML-Enhanced Honeypot — Server Installer       ║${RESET}"
echo -e "${RED}${BOLD}║    OS: ${OS}$(printf '%*s' $((34 - ${#OS})) '')║${RESET}"
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Python
# ═══════════════════════════════════════════════════════════════════════════════
step "1 / 6  Python"

PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3; do
  if command -v "$cmd" &>/dev/null; then
    VER=$("$cmd" -c "import sys; print(sys.version_info[:2])")
    if "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"; then
      PYTHON="$cmd"
      ok "Found $cmd  ($VER)"
      break
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  warn "Python 3.10+ not found. Installing..."
  if [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew &>/dev/null; then
      info "Installing Homebrew..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python@3.11
    PYTHON="python3.11"
  elif [[ -f /etc/debian_version ]]; then
    apt-get update -qq
    apt-get install -y python3 python3-pip python3-venv
    PYTHON="python3"
  elif command -v dnf &>/dev/null; then
    dnf install -y python3 python3-pip
    PYTHON="python3"
  elif command -v yum &>/dev/null; then
    yum install -y python3 python3-pip
    PYTHON="python3"
  else
    error "Cannot auto-install Python on this OS. Install Python 3.10+ manually."
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Node.js (dashboard)
# ═══════════════════════════════════════════════════════════════════════════════
step "2 / 6  Node.js (web dashboard)"

if command -v node &>/dev/null && node -e "process.exit(parseInt(process.versions.node)>=18?0:1)"; then
  ok "Node.js $(node --version) found."
else
  warn "Node.js 18+ not found. Installing..."
  if [[ "$OS" == "Darwin" ]]; then
    brew install node@20
    brew link node@20 --force --overwrite || true
  elif [[ -f /etc/debian_version ]]; then
    # NodeSource LTS repo
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
  elif command -v dnf &>/dev/null; then
    dnf install -y nodejs npm
  else
    warn "Cannot auto-install Node.js on this OS."
    warn "Install Node.js 18+ from https://nodejs.org and re-run."
  fi
fi

if command -v node &>/dev/null; then
  ok "Node.js $(node --version)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Copy files
# ═══════════════════════════════════════════════════════════════════════════════
step "3 / 6  Installing files to ${INSTALL_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$OS" == "Linux" ]]; then
  mkdir -p "$INSTALL_DIR"
  # Copy honeypot source
  cp -r "$SCRIPT_DIR/honeypot/." "$INSTALL_DIR/"
  # Copy dashboard
  mkdir -p "$INSTALL_DIR/honeypot-analytics"
  cp -r "$SCRIPT_DIR/honeypot-analytics/." "$INSTALL_DIR/honeypot-analytics/"
  chown -R root:root "$INSTALL_DIR"
  chmod -R 750 "$INSTALL_DIR"
  ok "Files installed to $INSTALL_DIR"
else
  # macOS — install to user's home
  INSTALL_DIR="$HOME/honeypot"
  mkdir -p "$INSTALL_DIR"
  cp -r "$SCRIPT_DIR/honeypot/." "$INSTALL_DIR/"
  mkdir -p "$INSTALL_DIR/honeypot-analytics"
  cp -r "$SCRIPT_DIR/honeypot-analytics/." "$INSTALL_DIR/honeypot-analytics/"
  ok "Files installed to $INSTALL_DIR"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Python dependencies + .env
# ═══════════════════════════════════════════════════════════════════════════════
step "4 / 6  Python dependencies"

"$PYTHON" -m pip install --quiet --upgrade pip
"$PYTHON" -m pip install --quiet scikit-learn numpy requests python-dotenv
ok "Python packages installed."

# Create .env from example if not present
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
  if [[ -f "$INSTALL_DIR/.env.example" ]]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    warn ".env created from template — edit $INSTALL_DIR/.env to set email credentials."
    echo ""
    echo "  Required settings in .env:"
    echo "    SENDER_EMAIL=you@gmail.com"
    echo "    RECIPIENT_EMAIL=you@gmail.com"
    echo "    SENDER_PASSWORD=xxxx-xxxx-xxxx-xxxx  (Gmail App Password)"
    echo ""
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Train ML models
# ═══════════════════════════════════════════════════════════════════════════════
step "5 / 6  Training ML models"

if [[ -f "$INSTALL_DIR/data/honeypot_synthetic.json" ]]; then
  PYTHONPATH="$INSTALL_DIR" \
    "$PYTHON" "$INSTALL_DIR/ml/ml_pipeline.py" train \
    "$INSTALL_DIR/data/honeypot_synthetic.json" && ok "ML models trained." \
    || warn "ML training failed — honeypot will run without ML scoring. Try manually: PYTHONPATH=$INSTALL_DIR $PYTHON $INSTALL_DIR/ml/ml_pipeline.py train $INSTALL_DIR/data/honeypot_synthetic.json"
else
  warn "Training data not found. Skipping ML training."
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Register as system service
# ═══════════════════════════════════════════════════════════════════════════════
step "6 / 6  System service"

if [[ "$NO_SERVICE" == true ]]; then
  warn "--no-service flag set. Skipping service registration."
  echo ""
  echo "  To start manually:"
  echo "    sudo PYTHONPATH=$INSTALL_DIR $PYTHON $INSTALL_DIR/honeypot.py"
  echo "    cd $INSTALL_DIR/honeypot-analytics && npm install && npm run start"
elif [[ "$OS" == "Linux" ]]; then

  # ── systemd unit: honeypot ────────────────────────────────────────────────
  PYTHON_ABS=$(command -v "$PYTHON")
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=ML-Enhanced Honeypot
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="PYTHONPATH=${INSTALL_DIR}"
Environment="HONEYPOT_BASE_DIR=${INSTALL_DIR}"
Environment="HONEYPOT_LOG_FILE=${INSTALL_DIR}/honeypot.log"
Environment="HONEYPOT_MODELS_DIR=${INSTALL_DIR}/models"
ExecStart=${PYTHON_ABS} ${INSTALL_DIR}/honeypot.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=honeypot

[Install]
WantedBy=multi-user.target
EOF

  # ── systemd unit: honeypot-dashboard ─────────────────────────────────────
  NODE_ABS=$(command -v node 2>/dev/null || echo "node")
  NPM_ABS=$(command -v npm 2>/dev/null || echo "npm")

  # Build dashboard
  info "Building Next.js dashboard..."
  (
    cd "$INSTALL_DIR/honeypot-analytics"
    "$NPM_ABS" install --silent
    HONEYPOT_LOG_FILE="$INSTALL_DIR/honeypot.log" "$NPM_ABS" run build --silent
  ) && ok "Dashboard built." || warn "Dashboard build failed — run manually: cd $INSTALL_DIR/honeypot-analytics && npm install && npm run build"

  cat > "/etc/systemd/system/${DASHBOARD_SERVICE_NAME}.service" <<EOF
[Unit]
Description=Honeypot Analytics Dashboard
After=network.target ${SERVICE_NAME}.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/honeypot-analytics
Environment="NODE_ENV=production"
Environment="PORT=${DASHBOARD_PORT}"
Environment="HONEYPOT_LOG_FILE=${INSTALL_DIR}/honeypot.log"
ExecStart=${NPM_ABS} run start
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=honeypot-dashboard

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl enable "$DASHBOARD_SERVICE_NAME"
  systemctl start  "$SERVICE_NAME"
  systemctl start  "$DASHBOARD_SERVICE_NAME"

  ok "systemd services enabled and started."
  echo ""
  info "Service commands:"
  echo "   sudo systemctl status  $SERVICE_NAME"
  echo "   sudo systemctl restart $SERVICE_NAME"
  echo "   sudo systemctl stop    $SERVICE_NAME"
  echo "   sudo journalctl -u $SERVICE_NAME -f      (live logs)"
  echo ""
  info "Dashboard:"
  echo "   sudo systemctl status  $DASHBOARD_SERVICE_NAME"
  echo "   http://localhost:${DASHBOARD_PORT}"

elif [[ "$OS" == "Darwin" ]]; then

  PYTHON_ABS=$(command -v "$PYTHON")
  LAUNCHD_DIR="$HOME/Library/LaunchAgents"
  mkdir -p "$LAUNCHD_DIR"

  # ── launchd plist: honeypot ───────────────────────────────────────────────
  cat > "$LAUNCHD_DIR/com.honeypot.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>           <string>com.honeypot</string>
  <key>ProgramArguments</key>
  <array>
    <string>${PYTHON_ABS}</string>
    <string>${INSTALL_DIR}/honeypot.py</string>
  </array>
  <key>WorkingDirectory</key><string>${INSTALL_DIR}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PYTHONPATH</key>               <string>${INSTALL_DIR}</string>
    <key>HONEYPOT_BASE_DIR</key>        <string>${INSTALL_DIR}</string>
    <key>HONEYPOT_LOG_FILE</key>        <string>${INSTALL_DIR}/honeypot.log</string>
    <key>HONEYPOT_MODELS_DIR</key>      <string>${INSTALL_DIR}/models</string>
  </dict>
  <key>RunAtLoad</key>       <true/>
  <key>KeepAlive</key>       <true/>
  <key>StandardOutPath</key> <string>${INSTALL_DIR}/honeypot-stdout.log</string>
  <key>StandardErrorPath</key><string>${INSTALL_DIR}/honeypot-stderr.log</string>
</dict>
</plist>
EOF

  # ── launchd plist: honeypot-dashboard ─────────────────────────────────────
  NPM_ABS=$(command -v npm 2>/dev/null || echo "npm")

  info "Building Next.js dashboard..."
  (
    cd "$INSTALL_DIR/honeypot-analytics"
    "$NPM_ABS" install --silent
    HONEYPOT_LOG_FILE="$INSTALL_DIR/honeypot.log" "$NPM_ABS" run build --silent
  ) && ok "Dashboard built." || warn "Dashboard build failed — run manually."

  cat > "$LAUNCHD_DIR/com.honeypot.dashboard.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>           <string>com.honeypot.dashboard</string>
  <key>ProgramArguments</key>
  <array>
    <string>${NPM_ABS}</string>
    <string>run</string>
    <string>start</string>
  </array>
  <key>WorkingDirectory</key><string>${INSTALL_DIR}/honeypot-analytics</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NODE_ENV</key>                  <string>production</string>
    <key>PORT</key>                      <string>${DASHBOARD_PORT}</string>
    <key>HONEYPOT_LOG_FILE</key>         <string>${INSTALL_DIR}/honeypot.log</string>
  </dict>
  <key>RunAtLoad</key>       <true/>
  <key>KeepAlive</key>       <true/>
  <key>StandardOutPath</key> <string>${INSTALL_DIR}/dashboard-stdout.log</string>
  <key>StandardErrorPath</key><string>${INSTALL_DIR}/dashboard-stderr.log</string>
</dict>
</plist>
EOF

  launchctl load "$LAUNCHD_DIR/com.honeypot.plist"
  launchctl load "$LAUNCHD_DIR/com.honeypot.dashboard.plist"
  ok "launchd agents loaded (auto-start on login)."

  echo ""
  warn "macOS: Ports below 1024 require root. To bind SSH/HTTP etc.:"
  echo "   sudo launchctl load $LAUNCHD_DIR/com.honeypot.plist"
  echo ""
  info "Service commands:"
  echo "   launchctl stop  com.honeypot"
  echo "   launchctl start com.honeypot"
  echo "   tail -f $INSTALL_DIR/honeypot-stdout.log"
  echo ""
  info "Dashboard: http://localhost:${DASHBOARD_PORT}"

else
  warn "Unknown OS '$OS'. Skipping service registration."
  echo "  Start manually:"
  echo "    sudo PYTHONPATH=$INSTALL_DIR $PYTHON $INSTALL_DIR/honeypot.py"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Done
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║         INSTALLATION COMPLETE                    ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Config file:${RESET}  $INSTALL_DIR/.env"
echo -e "  ${BOLD}Log file:${RESET}     $INSTALL_DIR/honeypot.log"
echo -e "  ${BOLD}IOC export:${RESET}   $INSTALL_DIR/ioc_export.json"
echo -e "  ${BOLD}Dashboard:${RESET}    http://localhost:${DASHBOARD_PORT}"
echo ""
echo -e "  ${YELLOW}ACTION REQUIRED: Edit $INSTALL_DIR/.env${RESET}"
echo -e "  Set SENDER_EMAIL, RECIPIENT_EMAIL, SENDER_PASSWORD for email alerts."
echo ""
echo -e "  To uninstall: sudo bash uninstall.sh"
echo ""
