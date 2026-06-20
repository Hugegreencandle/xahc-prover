#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ln -sf ../../scripts/git-pre-push-soundness.sh "$ROOT/.git/hooks/pre-push"
echo "installed pre-push soundness gate -> .git/hooks/pre-push"
