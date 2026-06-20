"""Prove the EMIT-DST-LOCK invariant — an autonomous Hook pays ONLY the locked payee.

Companion to prove_emit_budget. Where emit-budget bounds HOW MUCH an autonomous primitive emits,
this bounds WHERE it emits: every payment the Hook emits must go to the locked payee PAY (a 20-byte
account-id install param). For a Cron-fired subscription/vesting/streaming Hook — unattended, weak-TSH,
NO rollback (docs/CRON-GROUND-TRUTH.md) — paying the wrong address is an irreversible drain, so it must
be PROVEN, not trusted.

THE INVARIANT: param "PAY" (20-byte account-id). For ALL inputs, on EVERY accepting path, EVERY emitted
native Payment's Destination == PAY.

Fail-closed (a false PROVEN lets an autonomous Hook pay an attacker — catastrophic):
  • Uses the engine's parsed per-emit routing fields (emit_obs: {amount, dest(20 BitVec8), ...}). If an
    emit's obs is None — i.e. NOT the recognized native-payment template (an IOU emit / unrecognized
    blob whose destination the engine cannot read) — we CANNOT verify where it goes -> INCONCLUSIVE.
  • N/A if the hook reads no PAY param or never emits (the lock property isn't exercised).
  • solver `unknown` -> INCONCLUSIVE; unsound_gate (float/unsupported/bound) runs BEFORE any PROVEN.

Usage: python prove_emit_dst_lock.py <hook.wasm>
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    pay = e.inputs.get("param:PAY")
    if not pay or len(pay) != 20:
        print("— N/A — hook reads no 20-byte PAY (locked-payee) param; the emit-dst-lock property is "
              "not exercised. Not claimed.")
        return 1

    n = len(e.accepts_full)
    if len(e.emit_obs_on_accept) != n:
        print("\n⚠️ INCONCLUSIVE — accept/emit-obs path lists are not aligned; refusing PROVEN.")
        return 3

    n_emit_paths = 0
    for i in range(n):
        code, cons, _writes = e.accepts_full[i]
        _, obs_list, emit_count = e.emit_obs_on_accept[i]
        if not feasible(cons):
            continue
        if emit_count == 0:
            continue                              # no emit -> the lock is vacuously satisfied
        # every emit on this path must be the recognized native template AND go to PAY
        if len(obs_list) < emit_count or any(o is None for o in obs_list):
            print(f"\n⚠️ INCONCLUSIVE [emit-dst-lock] — accept code {code} emits a txn whose destination "
                  "the engine could not read (IOU/unrecognized template); cannot verify the payee. Not PROVEN.")
            return 3
        n_emit_paths += 1
        for o in obs_list:
            dest = o["dest"]                      # list[20 BitVec8]
            mismatch = z3.Or(*[dest[j] != pay[j] for j in range(20)])
            s = z3.Solver(); s.set("timeout", 20000)
            s.add(*cons)
            s.add(mismatch)                       # ...an emitted payment to a NON-payee address
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE [emit-dst-lock] — solver `unknown` on an accept path; not PROVEN.")
                return 3
            if r == z3.sat:
                m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
                dv = bytes(ev(b) for b in dest)
                pv = bytes(ev(b) for b in pay)
                print("\n❌ COUNTEREXAMPLE [emit-dst-lock] — an accepting path emits a payment to a "
                      f"NON-payee address (accept code {code}):")
                print(f"     emitted dest = {dv.hex().upper()}")
                print(f"     locked PAY   = {pv.hex().upper()}")
                return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    if n_emit_paths == 0:
        print("— N/A — no accepting path emits a payment; the emit-dst-lock property is not exercised.")
        return 1

    print("\n✅ PROVEN [emit-dst-lock] — for ALL inputs, every emitted Payment on every accepting path "
          "goes to the locked payee PAY. The autonomous Hook cannot pay any other address.")
    print("   SCOPE: native (XAH) emits whose destination the engine reads from the payment template; "
          "an IOU/unrecognized emit fails closed (INCONCLUSIVE), never PROVEN.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
