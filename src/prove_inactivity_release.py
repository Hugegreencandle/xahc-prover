"""Prove INACTIVITY-RELEASE (dead-man-switch): release ONLY after the owner has been inactive >= TIMEOUT.

The invariant behind a dead-man-switch / inheritance / recovery Hook: funds release to a beneficiary
only once the owner has gone silent for at least TIMEOUT seconds. We prove, for ALL inputs:

    accept-with-emit  =>  ledger_last_time() - last_seen >= TMO   (computed without underflow)

where `last_seen` (the owner's most-recent-activity chain time) is the prior value of state slot 0x02,
and TMO is param "TMO" (8B BE seconds). ledger_last_time is SYMBOLIC -> proven for EVERY time. The
subtraction is checked at 128-bit width as `now >= last_seen + TMO` so a clock-rewind or an overflow
cannot fake the timeout.

Fail-closed (a false PROVEN certifies a Hook that can release while the owner is still active — theft):
  • TMO absent -> N/A (not a dead-man-switch Hook).
  • If the Hook EMITS but never reads ledger_last_time, OR never reads the last_seen slot (0x02), the
    release cannot depend on inactivity -> COUNTEREXAMPLE (it can fire while the owner is active).
  • N/A if no accepting path emits. solver unknown -> INCONCLUSIVE; unsound_gate before any PROVEN.

Usage: python prove_inactivity_release.py <hook.wasm>
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate

LAST_SEEN_KEY = "\x02"   # state slot holding the owner's most-recent-activity time
W = 128                  # widen now/last_seen/TMO before the add+compare so it can't wrap


def _w(bv):
    return z3.ZeroExt(W - bv.size(), bv) if bv.size() < W else bv


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    tmo_b = e.inputs.get("param:TMO")
    if not tmo_b:
        print("— N/A — hook reads no TMO (inactivity timeout) param; the inactivity-release property is "
              "not exercised. Not claimed.")
        return 1
    TMO = _w(z3.Concat(*tmo_b) if len(tmo_b) > 1 else tmo_b[0])
    now = e.inputs.get("ledger_last_time")
    last_seen_bytes = e.state_old.get(LAST_SEEN_KEY)
    if LAST_SEEN_KEY in e.state_old_overwritten:
        print("\n⚠️ INCONCLUSIVE — the last-seen slot was read at inconsistent byte-widths (ambiguous "
              "prior model); refusing PROVEN (fail closed).")
        return 3
    if last_seen_bytes is not None and len(last_seen_bytes) != 8:
        print(f"\n⚠️ INCONCLUSIVE — the last-seen slot was read at {len(last_seen_bytes)} bytes, not the "
              "expected 8; cannot decode the prior activity time. Not PROVEN.")
        return 3

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
            continue
        n_emit_paths += 1
        if now is None or not last_seen_bytes:
            why = "ledger_last_time" if now is None else "the last-seen slot (0x02)"
            print(f"\n❌ COUNTEREXAMPLE [inactivity-release] — accept code {code} EMITS but the hook never "
                  f"reads {why}: the release cannot depend on owner inactivity, so it can fire while the "
                  "owner is still active.")
            return 2
        nw = _w(now)
        last_seen = _w(z3.Concat(*last_seen_bytes))   # guaranteed 8 bytes by the guard above
        s = z3.Solver(); s.set("timeout", 20000)
        s.add(*cons)
        s.add(z3.ULT(nw, last_seen + TMO))    # ...emits while now < last_seen + TMO (not inactive enough)
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [inactivity-release] — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE [inactivity-release] — an accepting path releases while the owner is "
                  f"still active (accept code {code}): now = {ev(nw)}, last_seen = {ev(last_seen)}, "
                  f"TMO = {ev(TMO)}; now - last_seen < TMO.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    if n_emit_paths == 0:
        print("— N/A — no accepting path emits a payment; the inactivity-release property is not exercised.")
        return 1

    print("\n✅ PROVEN [inactivity-release] — for ALL inputs, every emitting accept path requires "
          "ledger_last_time >= last_seen + TMO. The Hook releases ONLY after the owner has been inactive "
          "for at least TMO seconds; any owner activity (which updates last_seen) resets the timer.")
    print("   SCOPE: timeout via chain time; last_seen is the prior 0x02 slot. Pairs with emit-budget + "
          "emit-dst-lock + trigger-lock to certify a dead-man-switch.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
