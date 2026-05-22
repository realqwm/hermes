#!/usr/bin/env bash
# Build and release Hermes Agent
#
# Usage:
#   ./scripts/build_and_release.sh              # build only (dry run)
#   ./scripts/build_and_release.sh --release    # build + release (dry run)
#   ./scripts/build_and_release.sh --publish    # build + release + publish
#   ./scripts/build_and_release.sh --bump minor --publish  # full publish
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BUMP=""
PUBLISH=false
RELEASE=false
SKIP_FRONTEND=false

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --bump major|minor|patch  SemVer bump level (for release)
  --release                 Run release steps (changelog, tag, GitHub release)
  --publish                 Actually publish (default is dry run)
  --skip-frontend           Skip web/TUI frontend builds
  -h, --help                Show this help

Examples:
  $0                              # build only
  $0 --release                    # build + dry run release preview
  $0 --release --publish          # build + publish release
  $0 --bump minor --publish       # build + bump + publish
  $0 --skip-frontend --release    # skip npm builds, just Python
EOF
  exit 0
}

# ── parse args ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bump)         BUMP="$2"; shift 2 ;;
    --publish)      PUBLISH=true; RELEASE=true; shift ;;
    --release)      RELEASE=true; shift ;;
    --skip-frontend) SKIP_FRONTEND=true; shift ;;
    -h|--help)      usage ;;
    *)              echo -e "${RED}Unknown option: $1${NC}"; usage ;;
  esac
done

# ── helpers ─────────────────────────────────────────────────────────────
section()  { echo -e "\n${GREEN}===${NC} $1 ${GREEN}===${NC}"; }
step()     { echo -e "  ${YELLOW}→${NC} $1"; }
ok()       { echo -e "  ${GREEN}✓${NC} $1"; }
fail()     { echo -e "  ${RED}✗${NC} $1"; exit 1; }

# ── build ───────────────────────────────────────────────────────────────
section "Building Hermes Agent"

# 1. Frontend: web dashboard
if [ "$SKIP_FRONTEND" = false ] && [ -d web ]; then
  step "Building web dashboard..."
  (cd web && npm ci && npm run build) || fail "web dashboard build failed"
  ok "web dashboard built"
else
  step "Skipping web dashboard build"
fi

# 2. Frontend: TUI bundle
if [ "$SKIP_FRONTEND" = false ] && [ -d ui-tui ]; then
  step "Building TUI bundle..."
  (cd ui-tui && npm ci && npm run build) || fail "TUI bundle build failed"
  ok "TUI bundle built"

  step "Copying TUI dist into hermes_cli..."
  mkdir -p hermes_cli/tui_dist
  cp ui-tui/dist/entry.js hermes_cli/tui_dist/entry.js
  ok "TUI dist copied"
else
  step "Skipping TUI build"
fi

# 3. Verify frontend assets
step "Verifying frontend assets..."
test -f hermes_cli/web_dist/index.html || fail "web_dist/index.html missing"
test -f hermes_cli/tui_dist/entry.js   || fail "tui_dist/entry.js missing"
ok "Frontend assets verified"

# 4. Bundle install.sh
step "Bundling install.sh..."
mkdir -p hermes_cli/scripts
cp scripts/install.sh hermes_cli/scripts/install.sh
ok "install.sh bundled"

# 5. Python package
step "Building Python wheel and sdist..."
if command -v uv &>/dev/null; then
  uv build --sdist --wheel || fail "uv build failed"
else
  python -m build --sdist --wheel || fail "python build failed"
fi
ok "Python package built"

# List artifacts
echo ""
echo "  Build artifacts:"
for f in dist/*.whl dist/*.tar.gz; do
  [ -f "$f" ] && printf "    %s  %s\n" "$(du -h "$f" | cut -f1)" "$f"
done

section "Build complete"

# ── release ─────────────────────────────────────────────────────────────
if [ "$RELEASE" = true ]; then
  section "Release"

  RELEASE_ARGS=()
  [ -n "$BUMP" ] && RELEASE_ARGS+=("--bump" "$BUMP")
  [ "$PUBLISH" = true ] && RELEASE_ARGS+=("--publish")

  step "Running release script..."
  python scripts/release.py "${RELEASE_ARGS[@]}"
fi

echo ""
echo "Done."
