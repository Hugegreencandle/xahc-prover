"""Prove the spend-limit invariant: a hook never ACCEPTs when drops > LIM.

  for all inputs:  accept  =>  decoded(amount) <= decoded(LIM)

Usage: python prove_limit.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 1 = error.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate
from smt_export import emit_query


def main(path: str, max_drops: int | None = None) -> int:
    wasm = open(path, "rb").read()
    e = Engine(wasm)
    e.run()

    amt = e.inputs.get("amt")
    lim = e.inputs.get("param:LIM")
    if not amt or not lim:
        print("ERROR: hook does not read sfAmount and a LIM hook-param — not a spend-limit hook")
        return 1

    # spec: big-endian decode (byte 0 = most-significant), the intended meaning
    drops = z3.Concat(*amt)
    limit = z3.Concat(*lim)

    print(f"explored paths: {len(e.accepts)} accepting, {len(e.rollbacks)} rolling back")

    if max_drops is not None:
        print(f"(restricting to reachable inputs: drops <= {max_drops})")

    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        s.add(z3.UGT(drops, limit))   # an accept that lets drops exceed the limit
        if max_drops is not None:
            s.add(z3.ULE(drops, z3.BitVecVal(max_drops, 64)))  # only reachable amounts
        r = s.check()
        if r == z3.unknown:
            # SOUND: `unknown` is NOT proof there's no over-limit accept.
            print("\n⚠️ INCONCLUSIVE — the solver returned `unknown` (timeout/"
                  "incompleteness) checking an accepting path; cannot claim PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            av = [m.eval(b, model_completion=True).as_long() for b in amt]
            lv = [m.eval(b, model_completion=True).as_long() for b in lim]
            dv = int.from_bytes(bytes(av), "big")
            lvv = int.from_bytes(bytes(lv), "big")
            print("\n❌ COUNTEREXAMPLE — the hook ACCEPTS an over-limit payment:")
            print(f"   accept code {code}: drops={dv} > LIM={lvv}")
            print(f"   sfAmount bytes = {bytes(av).hex().upper()}")
            print(f"   LIM param bytes = {bytes(lv).hex().upper()}")
            return 2
        emit_query(s, "limit")  # unsat here: this path is proven — record the obligation

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the hook never accepts when drops > LIM.")
    return 0


if __name__ == "__main__":
    md = int(sys.argv[2]) if len(sys.argv) > 2 else None
    sys.exit(main(sys.argv[1], md))
