#!/usr/bin/env bash
# ==============================================================================
# Decebalus Setup Script
# Sets up all dependencies, database, and system configuration needed to run
# the Decebalus backend and frontend on a fresh system (Raspberry Pi OS / Debian).
# ==============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/decebalus-backend"
FRONTEND_DIR="$SCRIPT_DIR/decebalus-frontend"

step()    { echo -e "\n${BOLD}${BLUE}▶ $1${NC}"; }
ok()      { echo -e "  ${GREEN}✔${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
fail()    { echo -e "  ${RED}✘${NC} $1"; exit 1; }

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          Decebalus Setup Script          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""

# Guard: don't run as root — we use sudo where needed
if [ "$EUID" -eq 0 ]; then
    fail "Do not run this script as root. Run as a regular user; sudo will be invoked where needed."
fi

# ── 1. System packages ────────────────────────────────────────────────────────
step "Installing system packages"

if ! command -v apt-get &>/dev/null; then
    warn "apt-get not found — skipping system package install."
    warn "Please ensure the following are installed manually: curl, build-essential, pkg-config, libssl-dev, sqlite3, nmap"
else
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
        sqlite3 \
        nmap
    ok "System packages installed"
fi

# ── 2. Rust ───────────────────────────────────────────────────────────────────
step "Checking Rust / Cargo"

if ! command -v cargo &>/dev/null; then
    echo "  Rust not found — installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    ok "Rust installed: $(rustc --version)"
else
    # Ensure cargo env is sourced in case this shell doesn't have it
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env" 2>/dev/null || true
    ok "Rust already installed: $(rustc --version)"
fi

# ── 3. sqlx-cli ───────────────────────────────────────────────────────────────
step "Checking sqlx-cli"

if ! cargo sqlx --version &>/dev/null 2>&1; then
    echo "  sqlx-cli not found — installing (SQLite features only)..."
    cargo install sqlx-cli --no-default-features --features sqlite
    ok "sqlx-cli installed"
else
    ok "sqlx-cli already installed: $(cargo sqlx --version 2>&1)"
fi

# ── 4. Node.js / npm ──────────────────────────────────────────────────────────
step "Checking Node.js / npm"

if ! command -v node &>/dev/null; then
    echo "  Node.js not found — installing via NodeSource LTS..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    sudo apt-get install -y nodejs
    ok "Node.js installed: $(node --version), npm: $(npm --version)"
else
    ok "Node.js already installed: $(node --version), npm: $(npm --version)"
fi

# ── 5. Backend .env ───────────────────────────────────────────────────────────
step "Configuring backend environment"

ENV_FILE="$BACKEND_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    ok ".env already exists — leaving it untouched"
else
    cat > "$ENV_FILE" <<'EOF'
DATABASE_URL=sqlite:data/decebalus.db
LOG_RETENTION_DAYS=30
MAX_THREADS=5
MAX_DISCOVER_THREADS=256
MAX_SCAN_CONCURRENCY=500
EOF
    ok ".env created with defaults"
fi

# ── 6. Cargo dependencies ─────────────────────────────────────────────────────
step "Fetching Cargo dependencies"

cd "$BACKEND_DIR"
cargo fetch
ok "Cargo dependencies fetched"

# ── 7. Database setup ─────────────────────────────────────────────────────────
step "Setting up database"

mkdir -p "$BACKEND_DIR/data"
ok "data/ directory ready"

# sqlx commands need DATABASE_URL from .env
export $(grep -v '^#' "$ENV_FILE" | grep '=' | xargs)

cargo sqlx database create
ok "Database created (or already exists)"

cargo sqlx migrate run
ok "Migrations applied"

# ── 8. Frontend dependencies ──────────────────────────────────────────────────
step "Installing frontend dependencies"

cd "$FRONTEND_DIR"
npm install
ok "npm packages installed"

# ── 9. nmap sudoers rule ──────────────────────────────────────────────────────
step "Configuring nmap privileges"

SUDOERS_FILE="/etc/sudoers.d/decebalus-nmap"
SUDOERS_RULE="$USER ALL=(root) NOPASSWD: /usr/bin/nmap"

if [ -f "$SUDOERS_FILE" ]; then
    ok "nmap sudoers rule already in place"
else
    echo "$SUDOERS_RULE" | sudo tee "$SUDOERS_FILE" > /dev/null
    sudo chmod 0440 "$SUDOERS_FILE"
    # Validate the sudoers file is syntactically correct
    if sudo visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
        ok "nmap sudoers rule configured (enables OS detection + UDP scanning)"
    else
        sudo rm -f "$SUDOERS_FILE"
        warn "sudoers validation failed — nmap rule not installed. OS detection and UDP scanning will be skipped."
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║            Setup complete! ✔             ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Start the backend:${NC}"
echo -e "    cd decebalus-backend && cargo run"
echo ""
echo -e "  ${BOLD}Start the frontend (dev):${NC}"
echo -e "    cd decebalus-frontend && npm run dev"
echo ""
echo -e "  ${BOLD}Build the frontend for production:${NC}"
echo -e "    cd decebalus-frontend && npm run build"
echo ""
