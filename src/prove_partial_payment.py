"""Prove PARTIAL-PAYMENT safety — a Hook can't be tricked by tfPartialPayment.

  for all inputs:  accept  =>  the incoming Payment's Flags do NOT set tfPartialPayment

THE FOOTGUN (flagged by @Cbot_Xrpl, 2026-06-20): `tfPartialPayment` (0x00020000) lets the actually
DELIVERED amount arrive FAR below the `sfAmount` field. A Hook that gates accept on `sfAmount` thinks
it was paid in full when it got dust — tests pass, looks right, fully exploitable (the
delivered_amount-vs-Amount trap, Hooks side). The robust defense is to reject partial payments. This
proves that defense: no accepting path admits a payment with tfPartialPayment set.

Engine: the incoming tx's `sfFlags` (field code 0x20002 = (2<<16)+2, per xahaud hook/sfcodes.h) is
read via `otxn_field`; the engine exposes its symbolic bytes as inputs["otxn_field:20002"]. A hook
that NEVER reads/checks sfFlags leaves the flag attacker-controlled -> COUNTEREXAMPLE.

N/A (1) if the hook doesn't read sfAmount (not amount-gated -> a partial payment can't trick it).
Fail-closed: solver `unknown` / unsupported / hit bound -> INCONCLUSIVE, never PROVEN.
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate
from smt_export import emit_query

TF_PARTIAL_PAYMENT = 0x00020000
SF_FLAGS_KEY = "otxn_field:20002"          # sfFlags = (2<<16)+2 = 0x20002


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    # Only relevant to hooks that gate on the received amount. A hook that never reads sfAmount
    # can't be tricked by a dust delivered_amount -> N/A.
    if not any(k in e.inputs for k in ("amt", "amt48", "amt_xfl")):
        print("— N/A — hook does not read sfAmount (not amount-gated); a partial payment can't trick it.")
        return 1

    fb = e.inputs.get(SF_FLAGS_KEY)
    if fb and len(fb) >= 4:
        flags = z3.Concat(fb[0], fb[1], fb[2], fb[3])          # sfFlags UInt32, big-endian
        read_note = "hook reads sfFlags"
    else:
        # the hook never read sfFlags -> the incoming Flags is attacker-controlled, unconstrained.
        flags = z3.BitVec("otxn_flags_unread", 32)
        read_note = "hook does NOT read sfFlags (attacker-controlled)"

    is_partial = (flags & z3.BitVecVal(TF_PARTIAL_PAYMENT, 32)) != z3.BitVecVal(0, 32)
    print(f"explored: {len(e.accepts)} accepting path(s); {read_note}")

    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        s.add(is_partial)                  # an accept where the incoming payment IS a partial payment
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned unknown on a partial-payment query (fail closed).")
            return 3
        if r == z3.sat:
            print(f"\n❌ COUNTEREXAMPLE — an accepting path (code {code}) admits a tfPartialPayment txn: "
                  "the hook accepts a payment whose delivered amount can be far below sfAmount (dust).")
            return 2
        emit_query(s, "partial-payment")   # unsat here: this accepting path can't be a partial payment

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, accept ⟹ the incoming payment is NOT a partial payment "
          "(tfPartialPayment clear). The hook can't be tricked by a dust delivered_amount.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
