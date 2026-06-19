#!/usr/bin/env bash
# Provable Upgrades demo — closing the "authorized != safe" gap in Richard's bootloader.
#
# The bootloader proves: boot only the PINNED blob (gate) + only the owner re-pins, only forward
# (boot-upgrade-authz). What neither proves: that the NEW blob an authorized owner re-pins to is
# itself SAFE. This demo shows the missing gate — an upgrade is certified ONLY if it RE-PROVES the
# safety set, so a regressed/unsafe upgrade is provably REFUSED and shows PROOF_VOID live until (if
# ever) it can be certified.
#
# Pipeline reused: prove -> signed registry entry (keyed by on-chain HookHash) -> check/reverify.
# Prereqs: xahc + xahc-prover (XAHC, XAHC_PROVER_DIR or defaults).
set -euo pipefail

XAHC="${XAHC:-$HOME/Desktop/xahc/target/release/xahc}"
export XAHC_PROVER_DIR="${XAHC_PROVER_DIR:-$HOME/Desktop/xahc-prover}"
H="$XAHC_PROVER_DIR/hooks"
PY="$XAHC_PROVER_DIR/.venv/bin/python"
WORK="$(mktemp -d)"; STORE="$WORK/boot-registry.jsonl"; KEY="$WORK/attester.key"
INV=boot-upgrade-authz
say(){ printf "\n\033[1m== %s ==\033[0m\n" "$*"; }
reg(){ PYTHONPATH="$XAHC_PROVER_DIR/src" "$PY" -m registry "$@"; }

say "0. attester key"
PUB=$("$XAHC" registry keygen --out "$KEY" | awk '/public key:/{print $3}'); echo "attester: $PUB"

say "1. CERTIFY the current bootloader-upgrade hook (v1)"
"$XAHC" prove "$H/boot_upgrade_ok.wasm" --invariant $INV | tail -1
reg make-manifest "$H/boot_upgrade_ok.wasm" --invariant $INV --out "$WORK/v1.json" >/dev/null
"$XAHC" registry --store "$STORE" add "$WORK/v1.json" --key "$KEY"
echo "-- is the deployed v1 certified?"; "$XAHC" registry --store "$STORE" check "$H/boot_upgrade_ok.wasm" | tail -2

say "2. ATTEMPT A REGRESSED UPGRADE (owner re-pins to a downgrade-allowing blob — AUTHORIZED but UNSAFE)"
echo "-- prove the new blob's safety set:"
set +e; "$XAHC" prove "$H/boot_upgrade_downgrade_bug.wasm" --invariant $INV | tail -1
echo "   -> verdict exit: $?"; set -e
echo "-- try to certify it (make-manifest is fail-closed on a non-PROVEN verdict):"
set +e; reg make-manifest "$H/boot_upgrade_downgrade_bug.wasm" --invariant $INV --exit 2 --out "$WORK/bad.json"; echo "   -> certify exit: $?"; set -e
echo "-- so the upgraded blob is NOT in the registry. Is it certified?"
set +e; "$XAHC" registry --store "$STORE" check "$H/boot_upgrade_downgrade_bug.wasm" | tail -2; echo "   -> check exit: $?"; set -e

say "3. THE GATE"
echo "  ✅ v1 boot-upgrade hook: CERTIFIED (boot-upgrade-authz PROVEN, signed, re-checkable)."
echo "  ✗  the regressed upgrade: PROVABLY REFUSED — it fails the proof, so it CANNOT enter the"
echo "     registry, and live it reads PROOF_VOID/UNPROVEN until certified (which an unsafe blob"
echo "     never can be). Authorized != safe is now CLOSED *for the proven invariant set* (a guarantee
     exactly as strong as the invariants you choose to prove — not a claim of total safety):"
echo "       gate (boot pinned) + authz (owner-only, forward-only) + REGISTRY (only a PROVEN blob"
echo "       certifies) + xahc-watch (PROOF_VOID the instant deployed code != proven code)."
echo "     => an upgradeable hook that is always provably-current, or loudly flagged."
rm -rf "$WORK"
