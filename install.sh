#!/usr/bin/env bash
# Decebalus installer — builds the backend + web UI and checks external tooling.
# Intended for a Kali/Debian attack box. Re-run any time to rebuild.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "==> Decebalus install"

# Rust toolchain
if ! command -v cargo >/dev/null 2>&1; then
  echo "!! cargo not found. Install Rust from https://rustup.rs and re-run." >&2
  exit 1
fi

# Build the web UI (optional — only if node is available).
if command -v npm >/dev/null 2>&1; then
  echo "==> Building web UI"
  ( cd decebalus-frontend && npm ci && npm run build )
else
  echo "!! npm not found — skipping web UI build (run it separately with 'npm run dev')."
fi

echo "==> Building backend (release)"
( cd decebalus-backend && cargo build --release )

echo "==> Building terminal war table (TUI)"
( cd decebalus-backend && cargo build --release --features tui --bin decebalus-tui )

echo "==> Checking external tool dependencies"
( cd decebalus-backend && cargo run --release -- doctor ) || true

cat <<'EOF'

==> Done.
Run the server:   (cd decebalus-backend && cargo run --release)
Then open:        http://localhost:8080  (serves the web War Table)
Terminal UI:      (cd decebalus-backend && cargo run --release --features tui --bin decebalus-tui)

Optional hardening: export DECEBALUS_TOKEN=<secret> to require bearer auth.
EOF
