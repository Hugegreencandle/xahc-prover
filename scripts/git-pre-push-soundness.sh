#!/usr/bin/env bash
# Pre-push soundness gate: block a push that introduces a FALSE PROVEN (an invariant certifying a
# known-unsafe hook). Normally 0 false-proven -> passes in seconds, invisible. Only stops a genuine
# soundness regression. Install via scripts/install-git-hooks.sh. (Bypass once with git's skip-hooks flag.)
set -euo pipefail
# Resolve the repo root robustly (the hook is a symlink; BASH_SOURCE-relative paths land in .git/).
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || { echo "[soundness gate] no venv at $PY — skipping"; exit 0; }
echo "[soundness gate] false-PROVEN tripwire (--fast)..."
if ! "$PY" "$ROOT/tools/soundness_loop.py" --fast; then
  echo "[soundness gate] BLOCKED: a false PROVEN is present — an invariant certified a known-unsafe hook. Fix it before pushing."
  exit 1
fi
echo "[soundness gate] OK — no false PROVEN."
