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
    amt48 = e.inputs.get("amt48")

    # ---- IOU emit path: if any accepting path emits an ISSUED amount, the only
    #      sound verdict for value-conservation is INCONCLUSIVE whenever the emitted
    #      XFL was over-approximated (a symbolic nonlinear float op). We NEVER claim
    #      PROVEN over an over-approximated emitted value. (Native drops are handled
    #      by the original logic below.) Checked BEFORE the incoming-amount guard,
    #      since an IOU emitter need not read an incoming native amount.
    iou_emitting = any(
        cnt > 0 and any(x is not None for x in eiou)
        for _, eiou, cnt in e.iou_emits_on_accept
    )
    if not amt and not amt48 and not iou_emitting:
        print("ERROR: hook never reads sfAmount — no incoming value to conserve against.")
        return 1

    if iou_emitting:
        print(f"explored: {len(e.iou_emits_on_accept)} accepting path(s) (issued/IOU emit detected)")
        if e.float_overapprox:
            print(f"\n⚠️ INCONCLUSIVE — emitted IOU value(s) depend on over-approximated "
                  f"float op(s) {sorted(e.float_overapprox)} (symbolic nonlinear); the emitted "
                  f"value cannot be computed soundly. Refusing to claim conservation (PROVEN).")
            return 3
        if e.unsupported:
            print(f"\n⚠️ INCONCLUSIVE — unsupported op(s) {sorted(e.unsupported)} reached; "
                  f"cannot prove conservation.")
            return 3
        if e.hit_bound:
            print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; cannot prove.")
            return 3
        # SOUNDNESS (was a FALSE PROVEN): a concrete, un-tainted IOU emit is NOT proof of
        # conservation. The invariant is `Σ emitted <= received`, but this driver does NOT
        # model the INCOMING issued amount (currency + issuer + XFL) to compare against — so
        # a hook that emits a fixed IOU while receiving nothing (value creation) previously
        # printed "Balance conserved". We cannot decide `<= received` without the incoming
        # side, so we FAIL CLOSED. Real IOU conservation (per-currency/issuer matching + an
        # XFL inequality vs the incoming issued amount) is future work.
        print("\n⚠️ INCONCLUSIVE — IOU/issued-amount conservation is not modeled: the incoming "
              "issued amount is not compared against the emitted IOU, so `Σ emitted <= received` "
              "cannot be decided. Refusing to claim PROVEN (fail closed).")
        return 3

    if not amt:
        # Reached the native-conservation path but the hook read an incoming ISSUED
        # (IOU) amount (amt48), not native drops — we cannot soundly compare native
        # emits against an issued incoming value. Fail closed, never a false PROVEN.
        print("\n⚠️ INCONCLUSIVE — incoming amount is issued (IOU), not native drops; "
              "cannot compare native emit total against an issued incoming value.")
        return 3

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
            # Wording only — do NOT assert the source type (native vs issued). The amount
            # classifier can collide (an issued/IOU amount misread as native), so naming the
            # type here could mislead; the verdict (COUNTEREXAMPLE, never PROVEN) is unaffected.
            print("\n❌ COUNTEREXAMPLE — an accepting path's emitted value exceeds incoming "
                  "(value creation):")
            print(f"   incoming = {ev(incoming)} drops   emitted total = {ev(total)} drops "
                  f"across {count} payment(s)")
            return 2

    if e.float_overapprox:
        print(f"\n⚠️ INCONCLUSIVE — float op(s) {sorted(e.float_overapprox)} were "
              f"over-approximated (symbolic nonlinear); an over-approximated value may "
              f"reach the conservation invariant. Refusing to claim PROVEN.")
        return 3
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
