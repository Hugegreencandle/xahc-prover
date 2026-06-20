#!/usr/bin/env bash
# Proof-carrying hooks — a deploy-time gate (the Fomo/governance idea, working).
#
# The endgame for protocol-enforced verification: proving is off-chain (undecidable, expensive,
# one-time); the NETWORK only CHECKS the attached proof at deploy (cheap, decidable, deterministic).
# This demo is that gate. A deploy policy declares a REQUIRED invariant; a candidate hook is ADMITTED
# only if it carries a PROVEN proof, bound to its EXACT bytecode, for that invariant, AND the proof
# re-checks independently (checkproof = solver-free, engine out of the loop). No proof / wrong
# invariant / code≠proof  ->  REJECTED. Tiered: this gate enforces ONE invariant; a real policy lists
# the required set per account/permissioned-domain.
#
# Prereqs: xahc + xahc-prover (XAHC, XAHC_PROVER_DIR or defaults).
set -euo pipefail
XAHC="${XAHC:-$HOME/Desktop/xahc/target/release/xahc}"
export XAHC_PROVER_DIR="${XAHC_PROVER_DIR:-$HOME/Desktop/xahc-prover}"
H="$XAHC_PROVER_DIR/hooks"; PY="$XAHC_PROVER_DIR/.venv/bin/python"
WORK="$(mktemp -d)"; STORE="$WORK/deploy-registry.jsonl"; KEY="$WORK/k"; OBL="$WORK/obl"; mkdir -p "$OBL"
reg(){ PYTHONPATH="$XAHC_PROVER_DIR/src" "$PY" -m registry "$@"; }
say(){ printf "\n\033[1m== %s ==\033[0m\n" "$*"; }

REQUIRED_INVARIANT="guardrail"   # the deploy policy: hooks must be proven spend-safe (cap + dst lock)

say "0. setup — the proven hook carries a re-checkable proof object, registered to its HookHash"
"$XAHC" registry keygen --out "$KEY" >/dev/null
XAHC_EMIT_SMT="$OBL" "$XAHC" prove "$H/agent_guardrail.wasm" --invariant "$REQUIRED_INVARIANT" | tail -1
PYTHONPATH="$XAHC_PROVER_DIR/src" "$PY" -m registry make-manifest "$H/agent_guardrail.wasm" \
  --invariant "$REQUIRED_INVARIANT" --proof-object "$OBL" --out "$WORK/m.json" >/dev/null
reg --store "$STORE" add "$WORK/m.json" --key "$KEY"

# ── the deploy gate ───────────────────────────────────────────────────────────
gate(){  # gate <hook.wasm> <required_invariant> [obligation_dir]
  local wasm="$1" req="$2" obl="${3:-}"
  printf "\n  deploy %-26s (policy: must prove '%s')\n" "$(basename "$wasm")" "$req"
  local out; out="$("$XAHC" registry --store "$STORE" check "$wasm" 2>&1 || true)"
  if ! grep -q "✓ PROVEN" <<<"$out"; then   # NB: plain "PROVEN" substring-matches "UNPROVEN"
    echo "   ❌ REJECT — no proof bound to THIS exact bytecode (deployed code is not proven code). Blocked."; return 0
  fi
  if ! grep -q "$req" <<<"$out"; then
    echo "   ❌ REJECT — proven, but not for the required invariant '$req'. Blocked."; return 0
  fi
  if [ -n "$obl" ] && ! "$XAHC" registry --store "$STORE" checkproof "$obl" 2>&1 | grep -q "checkproof —"; then
    echo "   ❌ REJECT — the attached proof object failed independent re-check. Blocked."; return 0
  fi
  echo "   ✅ ADMIT — proven '$req', bound to this exact bytecode, proof re-checked (engine out of loop). Deploy allowed."
}

say "1. THE GATE — same policy, three candidate hooks"
gate "$H/agent_guardrail.wasm" "$REQUIRED_INVARIANT" "$OBL"   # the proven hook -> ADMIT
gate "$H/authz.wasm"           "$REQUIRED_INVARIANT"          # carries no proof -> REJECT
gate "$H/overflow.wasm"        "$REQUIRED_INVARIANT"          # different/unproven bytecode -> REJECT

say "2. THE POINT"
echo "  The network never ran the prover — it only CHECKED the proof (cheap, deterministic, fee-able)."
echo "  Proof-carrying hooks: prove off-chain, attach the proof, the protocol verifies it at deploy."
echo "  No proof = not admitted (not 'detected after the drain'). The safeguard lives in deployment."
echo "  Not a hard fork — a governance policy: require proven hooks for sensitive surfaces."
rm -rf "$WORK"
