"""Prove NATIVE-vs-IOU AMOUNT safety — a Hook can't be tricked into reading an issued (IOU)
STAmount's value word as native XAH drops.

  for all inputs:  accept  =>  the incoming sfAmount's not-XRP bit is CLEAR (byte0 & 0x80 == 0,
                               i.e. the amount really IS native XAH, not an issued token)

THE FOOTGUN: sfAmount is a polymorphic STAmount. A NATIVE XAH amount is an 8-byte value word with
bit 63 (byte0 & 0x80) CLEAR; an ISSUED (IOU) amount is a 48-byte STAmount whose first 8 bytes are an
XFL value word with bit 63 (byte0 & 0x80) SET. A hook that reads sfAmount into an 8-byte buffer and
decodes it as native drops — masking byte0 with 0x3F (per the native decode) but NEVER REJECTING
when the not-XRP bit is set — misreads an incoming IOU's XFL value word as some tiny drops number.
The attacker sends a HUGE issued token (whose masked value word looks like dust drops), passes the
hook's spend/limit/min-payment gate, and the hook accepts a transfer that is nothing like what it
thinks it received. (Native == 0x80 clear, issued == 0x80 set — see XAHAU-DEV-REFERENCE §6/§8 and
xahc otxn.h `xahc_otxn_drops`, which returns -2 NOT_XRP and rolls back on that bit.)

The robust defense (what `xahc_otxn_drops` does): after the 8-byte read, REJECT when byte0 & 0x80 is
set — only accept genuinely-native amounts. This proves that defense: no accepting path admits an
incoming amount whose not-XRP bit is set.

Engine: the 8-byte sfAmount read exposes inputs["amt"] = 8 symbolic bytes (byte0..byte7, big-endian
value word). bit 63 = `amt[0] & 0x80` is attacker-controlled and unconstrained on this path, so an
issued value word IS reachable through the 8-byte read. A hook that gates accept on the decoded drops
WITHOUT testing that bit leaves an accepting path with the bit SET -> COUNTEREXAMPLE.

SCOPE / N/A (1):
  - hook does NOT read sfAmount at all (no "amt"/"amt48") -> not amount-gated -> N/A.
  - hook reads sfAmount via the 48-byte ISSUED path ("amt48"/"amt_xfl") and NOT the 8-byte native
    path ("amt") -> it is deliberately handling IOUs in XFL space (prove with limit-iou /
    conservation), so the native-misread footgun does not apply -> N/A. (If it reads BOTH widths the
    native 8-byte path is still in scope and this invariant runs on it.)

Fail-closed: solver `unknown` / over-approx / unsupported / hit bound -> INCONCLUSIVE, never PROVEN.
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate, vacuity_guard
from smt_export import emit_query

NOT_XRP_BIT = 0x80          # byte0 bit7 (= value-word bit 63): set => issued (non-native) amount


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    amt = e.inputs.get("amt")
    if amt is None:
        # The hook never read the 8-byte NATIVE sfAmount.
        if any(k in e.inputs for k in ("amt48", "amt_xfl")):
            print("— N/A — hook reads sfAmount via the 48-byte ISSUED path only (handles IOUs in "
                  "XFL space); the native-misread footgun does not apply (use limit-iou / conservation).")
        else:
            print("— N/A — hook does not read sfAmount (not amount-gated); no native/IOU misread possible.")
        return 1

    if len(amt) < 1:
        print("\n⚠️ INCONCLUSIVE — the 8-byte sfAmount read exposed no bytes (cannot model byte0).")
        return 3

    # not-XRP bit lives in byte0 (the big-endian value word's most-significant byte).
    is_issued = (amt[0] & z3.BitVecVal(NOT_XRP_BIT, 8)) != z3.BitVecVal(0, 8)

    print(f"explored: {len(e.accepts)} accepting path(s); hook reads 8-byte native sfAmount")

    feasible_accepts = 0
    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        if s.check() == z3.unsat:
            continue                       # infeasible path: doesn't exercise the property
        feasible_accepts += 1
        s.add(is_issued)                   # an accept where the incoming amount is ISSUED (bit63 set)
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned unknown on a native/IOU query (fail closed).")
            return 3
        if r == z3.sat:
            print(f"\n❌ COUNTEREXAMPLE — an accepting path (code {code}) admits an ISSUED (IOU) "
                  "sfAmount read as native drops: byte0's not-XRP bit (0x80) is set, so the hook "
                  "decodes an issued token's XFL value word as a tiny drops value and accepts. "
                  "An attacker pays a huge IOU that looks like dust XAH.")
            return 2
        emit_query(s, "native-amount")     # unsat: this accepting path can't carry an issued amount

    # Vacuity: no feasible accept exercised the property -> N/A, never a vacuous PROVEN.
    code = vacuity_guard(feasible_accepts, "the incoming native sfAmount decode")
    if code is not None:
        return code

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, accept ⟹ the incoming sfAmount is genuinely NATIVE XAH "
          "(not-XRP bit clear). The hook cannot be tricked into reading an issued token as drops.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
