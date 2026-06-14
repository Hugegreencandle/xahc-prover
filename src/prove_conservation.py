"""Prove BALANCE CONSERVATION — a hook never emits more value than it received.

  for all inputs:  accept  =>  sum(emitted native drops)  <=  incoming drops

The dangerous bug is value creation: a forwarder/splitter that, on some input,
emits more XAH than the triggering payment delivered. The engine extracts the
native amount from each emitted Payment blob (xahc payment template) and the
incoming amount from sfAmount; this driver checks no accepting path emits a total
above what came in. If any emitted amount can't be parsed, the verdict is
INCONCLUSIVE — never a false PROVEN.

Usage: python prove_conservation.py <hook.wasm>
"""
import sys
import z3
from prover import Engine


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    amt = e.inputs.get("amt")
    if not amt:
        print("ERROR: hook never reads sfAmount — no incoming value to conserve against.")
        return 1
    incoming = z3.ZeroExt(64, z3.Concat(amt[0] & 0x3F, *amt[1:]))   # 128-bit, masked drops

    print(f"explored: {len(e.emits_on_accept)} accepting path(s)")

    for cons, emits, count in e.emits_on_accept:
        if count == 0:
            continue
        if any(x is None for x in emits):
            print("\n⚠️ INCONCLUSIVE — an emitted amount could not be parsed "
                  "(non-template payment); cannot claim conservation.")
            return 3
        total = z3.BitVecVal(0, 128)
        for x in emits:
            total = total + z3.ZeroExt(64, x)
        s = z3.Solver()
        s.add(*cons)
        s.add(z3.UGT(total, incoming))           # emitted MORE than received → value created
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned `unknown` (timeout/"
                  "incompleteness) on an accepting path; cannot claim conservation.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE — an accepting path emits MORE than it received "
                  "(value creation):")
            print(f"   incoming = {ev(incoming)} drops   emitted total = {ev(total)} drops "
                  f"across {count} payment(s)")
            return 2

    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} "
              f"(e.g. br_table / call_indirect) reached during analysis; cannot prove "
              f"conservation. Refusing to claim PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; deeper iterations "
              "were not explored. Cannot claim PROVEN.")
        return 3

    print("\n✅ PROVEN — for ALL inputs, the total emitted never exceeds the incoming "
          "amount. Balance is conserved; no value created.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
