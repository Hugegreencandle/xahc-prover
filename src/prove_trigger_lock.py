"""Prove TRIGGER-LOCK: an autonomous Hook emits ONLY on its own Cron fire.

A Cron-fired autonomous primitive (subscription, vesting, DCA, streaming) should move money ONLY when
driven by its own scheduled Cron (ttCRON), never when some arbitrary tx happens to touch the account
(an incoming Payment, an Invoke, ...). Without that gate a non-owner can TRIGGER an (capped, payee-
locked, but unintended) emit by sending the account any tx. This invariant proves the gate holds.

THE INVARIANT: for ALL inputs, on every accepting path that EMITS, otxn_type == ttCRON (92). I.e. no
accepting path emits a payment unless the triggering transaction is the account's own Cron pseudo-tx.

ttCRON == 92 (verified vs the xahau TRANSACTION_TYPES table; CronSet == 93). Generalizes to ANY
Cron-triggered money primitive.

Fail-closed (a false PROVEN would certify a hook that can be triggered by anyone — overspend pacing /
griefing risk):
  • If a hook EMITS but never reads otxn_type at all, the emit cannot depend on the trigger type -> it
    fires on ANY trigger -> COUNTEREXAMPLE (not a vacuous PROVEN).
  • N/A if no accepting path emits (the property isn't exercised).
  • solver `unknown` -> INCONCLUSIVE; unsound_gate runs BEFORE any PROVEN.

Usage: python prove_trigger_lock.py <hook.wasm>
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate

TT_CRON = 92   # the Cron pseudo-tx that fires the owner's hook as a weak TSH (CronSet=93)


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    tt = e.inputs.get("otxn_type")           # symbolic 64-bit otxn TransactionType, or None if unread
    n = len(e.accepts_full)
    if len(e.emits_on_accept) != n:
        print("\n⚠️ INCONCLUSIVE — accept/emit path lists are not aligned; refusing PROVEN.")
        return 3

    n_emit_paths = 0
    for i in range(n):
        code, cons, _writes = e.accepts_full[i]
        _, _emits, emit_count = e.emits_on_accept[i]
        if not feasible(cons):
            continue
        if emit_count == 0:
            continue                          # a non-emitting accept never moves money — no trigger to lock
        n_emit_paths += 1
        if tt is None:
            print(f"\n❌ COUNTEREXAMPLE [trigger-lock] — accept code {code} EMITS but the hook never reads "
                  "otxn_type: the emit cannot depend on the trigger, so it fires on ANY transaction (not "
                  "just its own Cron). A non-owner tx to the account would drive a payment.")
            return 2
        s = z3.Solver(); s.set("timeout", 20000)
        s.add(*cons)
        s.add(tt != z3.BitVecVal(TT_CRON, tt.size()))   # ...emits while the trigger is NOT a Cron fire
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [trigger-lock] — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            tv = m.eval(tt, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE [trigger-lock] — an accepting path emits a payment when the trigger "
                  f"is NOT a Cron fire (accept code {code}): otxn_type = {tv} (ttCRON = {TT_CRON}). A "
                  "non-Cron transaction to the account drives a payment.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    if n_emit_paths == 0:
        print("— N/A — no accepting path emits a payment; the trigger-lock property is not exercised.")
        return 1

    print("\n✅ PROVEN [trigger-lock] — for ALL inputs, every emitting accept path requires "
          f"otxn_type == ttCRON ({TT_CRON}). The autonomous Hook moves money ONLY on its own Cron fire; "
          "no arbitrary transaction to the account can trigger a payment.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
