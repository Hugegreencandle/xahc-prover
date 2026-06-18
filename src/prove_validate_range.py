"""Prove RANGE VALIDATION — OWASP SC04 (insufficient input validation), the bounds deepening.

  for all inputs:  accept  =>  param VAL is PRESENT  AND  LO <= VAL <= HI
                               (VAL lies within its declared [LO, HI] bounds)

This DEEPENS prove_validate (which proves only PRESENCE — accept ⟹ the param is set). The
classic SC04 footgun is reading a present param and trusting its VALUE without bounds-checking
it: an out-of-range config (a percentage > 100, a fee above the cap, an index past the end, a
divisor of 0) is accepted and used. Presence alone does not catch it.

CONTRACT (what a hook must read to be analyzable here):
  param "VAL" (8B BE) — the value being validated
  param "LO_" (8B BE) — the declared inclusive lower bound
  param "HI_" (8B BE) — the declared inclusive upper bound
A correct hook requires all three present and enforces LO <= VAL <= HI (unsigned) before
accepting. The driver checks: is it feasible to ACCEPT while VAL is OUTSIDE [LO, HI]?
  sat     -> COUNTEREXAMPLE (a missing/half bound check lets an out-of-range value through)
  all UNSAT across accept paths -> PROVEN.

Presence is also asserted (hook_param_ret:VAL >= 0) so a PROVEN is a strict superset of the
prove_validate presence guarantee.

Fail-closed: solver `unknown` / unsupported opcode / hit unroll bound => INCONCLUSIVE, never
PROVEN. A hook that does not read VAL/LO_/HI_ -> N/A (not this contract).

Usage: python prove_validate_range.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = N/A.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    val = e.inputs.get("param:VAL")
    lo = e.inputs.get("param:LO_")
    hi = e.inputs.get("param:HI_")
    if not (val and lo and hi):
        print("N/A — hook does not read the range contract params VAL / LO_ / HI_ (each 8-byte "
              "big-endian: the value and its declared inclusive [lower, upper] bounds). Not "
              "analyzable by this driver.")
        return 1

    VAL = z3.Concat(*val)
    LO = z3.Concat(*lo)
    HI = z3.Concat(*hi)
    ret_val = e.inputs.get("hook_param_ret:VAL")   # presence code (signed; < 0 = absent)

    # Non-vacuity (VR-02): a hook that reads VAL/LO_/HI_ but never accepts would make the
    # universal "accept ⟹ ..." obligation vacuously true. Disclose rather than print a clean PROVEN.
    if not e.accepts:
        print("N/A — the hook has 0 accepting paths; the accept ⟹ in-range obligation is "
              "vacuous, not claimed.")
        return 1

    print(f"explored: {len(e.accepts)} accepting path(s); checking VAL ∈ [LO_, HI_] (UNSIGNED)")

    for code, cons in e.accepts:
        # (presence) accept ⟹ VAL present — a strict superset of prove_validate.
        if ret_val is not None:
            s = z3.Solver(); s.set("timeout", 120000)
            s.add(*cons); s.add(ret_val < 0)
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE — solver `unknown` on a presence check; not PROVEN.")
                return 3
            if r == z3.sat:
                print("\n❌ COUNTEREXAMPLE — accepts while required param VAL is ABSENT "
                      "(fail-open): the unset value was trusted.")
                return 2

        # (range) accept ⟹ LO <= VAL <= HI, UNSIGNED. Negation: VAL below LO OR above HI.
        # SCOPE (VR-01): this contract is UNSIGNED (ULT/UGT). A hook validating a SIGNED int64
        # range (i64.ge_s/le_s) is judged under unsigned semantics — soundness-safe (never a false
        # PROVEN) but it can spuriously COUNTEREXAMPLE a correct signed hook. Signed-range support
        # is out of this driver's contract; the messages below say "unsigned" so the verdict is honest.
        s = z3.Solver(); s.set("timeout", 120000)
        s.add(*cons)
        s.add(z3.Or(z3.ULT(VAL, LO), z3.UGT(VAL, HI)))   # out of the declared range
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver `unknown` on a range check; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE — accepts a VAL OUTSIDE its declared [LO_, HI_] range "
                  "(unsigned):")
            print(f"   VAL={ev(VAL)}  LO_={ev(LO)}  HI_={ev(HI)}  "
                  f"({'below LO_' if ev(VAL) < ev(LO) else 'above HI_'}) — bounds not fully "
                  "enforced (a half/missing range check). NOTE: comparison is UNSIGNED; a signed "
                  "int64 range hook is out of this driver's contract.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the hook never accepts unless VAL is present AND within "
          "its declared [LO_, HI_] bounds (UNSIGNED LO_ <= VAL <= HI_). SC04 range validation: "
          "clean. (Scope: unsigned comparison; signed-range hooks are out of contract.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
