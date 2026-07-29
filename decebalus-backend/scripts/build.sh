#!/usr/bin/env bash
# Build a single, self-contained Decebalus binary: builds the Svelte frontend,
# then compiles the backend with `--features embed-ui` so the fresh `dist/`
# output gets baked into the executable. Re-run this any time the frontend
# changes — a plain `cargo build` alone will NOT pick up frontend edits, since
# Cargo only knows to re-embed because build.rs watches `dist/` for changes.
#
# Usage: scripts/build.sh [--debug]
#   --debug   build a debug binary instead of --release (faster, for local testing)
set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$BACKEND_DIR/.." && pwd)"
FRONTEND_DIR="$ROOT/decebalus-frontend"

PROFILE=release
CARGO_PROFILE_FLAG=--release
if [[ "${1:-}" == "--debug" ]]; then
  PROFILE=debug
  CARGO_PROFILE_FLAG=
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "!! npm not found — the frontend can't be built. Install Node.js and re-run." >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "!! cargo not found — install Rust from https://rustup.rs and re-run." >&2
  exit 1
fi

echo "==> Building frontend ($FRONTEND_DIR)"
( cd "$FRONTEND_DIR" && npm ci && npm run build )

echo "==> Building backend with embedded UI ($BACKEND_DIR, profile: $PROFILE)"
( cd "$BACKEND_DIR" && cargo build $CARGO_PROFILE_FLAG --features embed-ui )

BIN="$BACKEND_DIR/target/$PROFILE/decebalus-backend"
echo
echo "==> Done: $BIN"
echo "    Single self-contained binary — no FRONTEND_DIR or dist/ needed at runtime."
