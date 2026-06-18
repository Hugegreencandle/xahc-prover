"""Prove the EMISSION-BURDEN invariant (the STATIC reserve-count bound only).

  for all inputs:  accept  =>  emit_count  <=  reserved_n
                   where reserved_n = the count the hook passed to etxn_reserve(n)
                   (0 if the hook never called etxn_reserve)

Hoare triple (per accepting path):
  { the hook declared an emit budget reserved_n via etxn_reserve(n) (or 0 if it never did) }
  hook performs emit_count emit() calls and ACCEPTs
  { emit_count <= reserved_n }

Why it matters: xahaud requires every emitted txn to be reserved up front. Emitting MORE than
reserved is a runtime -13 TOO_MANY_EMITTED_TXN — the over-budget emit fails, leaving a partial /
failed emission. A hook that emits without ever reserving (reserved_n = 0, any emit) hits the
same failure. This driver proves, for ALL inputs, that no accepting path can exceed its own
declared reserve.

Proof obligation (negated, per accepting path):
  emit_count is a CONCRETE count the engine tracked exactly (loops are unrolled, calls inlined).
  reserved_n is the (possibly symbolic) 64-bit argument captured from the FIRST etxn_reserve.
  We ask Z3, under the path constraints: is  emit_count > reserved_n  feasible?
    sat     -> COUNTEREXAMPLE (an accepting path can over-emit its reserve)
    unknown -> INCONCLUSIVE (fail closed)
    all UNSAT across every accepting path -> the bound holds -> PROVEN (static scope).

=== SCOPE — read before trusting a PROVEN ===
This proves ONLY the static, single-invocation bound: accept => emit_count <= reserved_n within
one `hook` execution. It does NOT prove the dynamic property "emission generation / burden stays
bounded under cbak re-entry or emitted-txn loops". A `cbak` callback runs when an emitted txn
settles and may itself emit and/or call hook_again, growing the TOTAL emission burden across
re-entries the symbolic engine does NOT model (it analyzes a single hook invocation in isolation).

  *** FAIL CLOSED on the dynamic case ***
  If the module EXPORTS `cbak` (the re-entry surface) the unbounded-emission-chain property is
  NOT decidable here -> this driver returns INCONCLUSIVE (3), NEVER PROVEN. A PROVEN is only ever
  emitted for hooks with no cbak, where the static per-invocation reserve bound IS the whole story.

Do NOT describe a PROVEN from this driver as "no runaway emit". It is: "for all inputs, this
single hook invocation never emits more transactions than it reserved (static reserve-count bound)".

Usage: python prove_emission.py <hook.wasm>
Exit 0 = PROVEN (static bound), 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE / fail-closed, 1 = N/A.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    # --- FAIL CLOSED #1: the dynamic cbak / re-entry chain is out of scope. ---
    # A cbak callback is the re-entry surface where the emission burden can grow across emitted
    # -txn settlements (cbak may re-emit / hook_again). The engine models only a single `hook`
    # invocation, so we CANNOT prove the chain stays bounded. If cbak is exported, refuse to
    # claim PROVEN. (This precedes everything else so the dynamic case can never slip through.)
    if e.has_cbak:
        emits_anywhere = any(ec > 0 for _c, ec, _rn, _rc in e.emission_on_accept)
        note = ("emits and " if emits_anywhere else "")
        print(f"\n⚠️ INCONCLUSIVE — the hook exports a `cbak` callback ({note}re-entry can grow "
               "the emission burden across emitted-txn settlements / hook_again). cbak / "
               "re-entry emission chains are NOT modeled by this engine; it proves only the "
               "static per-invocation reserve-count bound. Refusing to claim PROVEN for the "
               "dynamic case.")
        return 3

    print(f"explored: {len(e.emission_on_accept)} accepting path(s); "
          "checking emit_count <= reserved per path")

    for cons, emit_count, reserve_n, reserve_calls in e.emission_on_accept:
        # The reserved budget: the captured first-etxn_reserve `n`, or 0 if the hook never
        # reserved (emitting at all is then already over budget).
        if reserve_n is None:
            reserved = z3.BitVecVal(0, 64)
        else:
            reserved = reserve_n  # BitVec64 (concrete or symbolic)

        emitted = z3.BitVecVal(emit_count, 64)   # EXACT concrete count the engine tracked

        s = z3.Solver()
        s.set("timeout", 120000)                 # fail closed (-> unknown -> INCONCLUSIVE)
        s.add(*cons)
        # NEGATION of the invariant: an accept where emit_count exceeds the reserved budget.
        # Unsigned compare — reserved_n is a uint32 count widened to 64-bit; emit_count >= 0.
        s.add(z3.UGT(emitted, reserved))
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned `unknown` (timeout/incompleteness) on an "
                  "accepting path while checking the reserve bound; cannot claim PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            rv = m.eval(reserved, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE — an accepting path emits more than it reserved:")
            print(f"   emit_count = {emit_count}  >  reserved = {rv}"
                  + ("  (hook never called etxn_reserve)" if reserve_n is None else "")
                  + "  -> runtime -13 TOO_MANY_EMITTED_TXN (failed/partial emit).")
            return 2

    # --- standard fail-closed gates (must precede any PROVEN) ---
    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, no accepting path emits more transactions than the hook "
          "reserved via etxn_reserve (static per-invocation reserve-count bound). No -13 "
          "TOO_MANY_EMITTED_TXN from over-emission. (SCOPE: this is the static bound only — the "
          "hook exports no cbak, so there is no re-entry emission chain to model.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
