"""Prove the agent_guardrail invariant — the REAL deployed hook.

  for all inputs:  (accept AND outgoing Payment)  =>  drops <= LIM

"outgoing Payment" is the hook's own condition: otxn_type == Payment(0) AND the
originating account == the hook's account (origin == hook_account, 20 bytes).
`drops` uses the guardrail's decode: byte 0 masked with 0x3F (strips the native /
sign flag bits), big-endian.

Usage: python prove_guardrail.py <agent_guardrail.wasm> [max_drops]
"""
import sys
import z3
from prover import Engine


def main(path: str, max_drops: int | None = None) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    amt = e.inputs.get("amt")
    lim = e.inputs.get("param:LIM")
    origin = e.inputs.get("origin")
    me = e.inputs.get("hookacc")
    tt = e.inputs.get("otxn_type")
    if not all([amt, lim, origin, me, tt is not None]):
        print("ERROR: hook does not look like agent_guardrail (needs otxn_type, sfAccount, hook_account, sfAmount, LIM)")
        return 1

    # the guardrail's amount decode masks byte0 with 0x3F (strips not-XRP/sign bits)
    drops = z3.Concat(amt[0] & 0x3F, *amt[1:])
    limit = z3.Concat(*lim)
    is_payment = tt == 0
    is_outgoing = z3.And(*[origin[i] == me[i] for i in range(20)])

    print(f"explored paths: {len(e.accepts)} accepting, {len(e.rollbacks)} rolling back")
    if max_drops is not None:
        print(f"(restricting to reachable inputs: drops <= {max_drops})")

    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        s.add(is_payment, is_outgoing)          # scope: an OUTGOING PAYMENT
        s.add(z3.UGT(drops, limit))             # ...that the hook still accepted over-limit
        if max_drops is not None:
            s.add(z3.ULE(drops, z3.BitVecVal(max_drops, 64)))
        if s.check() == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long()
            av = bytes(ev(b) for b in amt)
            lv = bytes(ev(b) for b in lim)
            dv = ((av[0] & 0x3F) << 56) | int.from_bytes(av[1:], "big")
            lvv = int.from_bytes(lv, "big")
            print("\n❌ COUNTEREXAMPLE — guardrail ACCEPTS an over-limit OUTGOING payment:")
            print(f"   accept code {code}: drops={dv} > LIM={lvv}")
            print(f"   sfAmount bytes = {av.hex().upper()}   LIM = {lv.hex().upper()}")
            return 2

    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; deeper iterations were not explored. Cannot claim PROVEN.")
        return 3

    print("\n✅ PROVEN — for ALL inputs, the guardrail never accepts an outgoing payment over LIM.")
    return 0


if __name__ == "__main__":
    md = int(sys.argv[2]) if len(sys.argv) > 2 else None
    sys.exit(main(sys.argv[1], md))
