"""Prove the IOU (issued-amount) spend-limit invariant in XFL space:

  for all inputs:  accept  =>  XFL(amount)  <=  XFL(LIM)

The incoming Amount is an issued STAmount (48 bytes); its 8-byte value word is an
XFL. LIM is an 8-byte XFL hook-param. Comparison is done with the SAME exact-order
XFL semantics the hook uses (float_compare), built from linear bit-vector
inequalities — never native byte arithmetic, which would be a wrong model.

Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = error.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    amtx = e.inputs.get("amt_xfl")
    lim = e.inputs.get("param:LIM")
    if amtx is None or not lim:
        print("ERROR: hook does not read a 48-byte issued sfAmount and a LIM hook-param "
              "— not an IOU spend-limit hook")
        return 1

    # LIM param bytes -> XFL value word (big-endian); clear the is-issued bit so a
    # LIM supplied either as raw XFL or as an issued value word both decode correctly.
    limx = z3.Concat(*lim[:8]) & z3.BitVecVal(0x7FFFFFFFFFFFFFFF, 64)

    # build c = signed XFL comparison(amt, lim) with the engine's EXACT ordering
    eng_cmp = e._float_cmp_c(amtx, limx)   # BV8 in {-1,0,1}; uses linear BV only

    print(f"explored paths: {len(e.accepts)} accepting, {len(e.rollbacks)} rolling back")

    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        # an accept that lets the amount EXCEED the limit (c == 1, i.e. amt > LIM)
        s.add(eng_cmp == z3.BitVecVal(1, 8))
        # keep the compared XFLs normalized (the only shape xahaud ever produces),
        # so a spurious denormal encoding can't manufacture a counterexample.
        s.add(e._float_normalized(amtx))
        s.add(e._float_normalized(limx))
        r = s.check()
        if r == z3.unknown:
            print("\nINCONCLUSIVE — the solver returned `unknown` (timeout/incompleteness) "
                  "checking an accepting path; cannot claim PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            av = m.eval(amtx, model_completion=True).as_long()
            lv = m.eval(limx, model_completion=True).as_long()
            print("\nCOUNTEREXAMPLE — the hook ACCEPTS an over-limit IOU payment:")
            print(f"   accept code {code}: amt XFL={av} > LIM XFL={lv}")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\nPROVEN — for ALL inputs, the hook never accepts when XFL(amount) > XFL(LIM).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
