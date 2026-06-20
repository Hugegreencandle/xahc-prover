"""Prove TIME-RELEASE (cliff gate): an autonomous Hook emits NOTHING before its unlock time.

The new invariant that unlocks the vesting / scheduled-release family. A vesting or timed-payout Hook
must not release funds before its cliff/start time. We prove, for ALL inputs:

    accept-with-emit  =>  ledger_last_time() >= CLIFF        (no release before the unlock time)

`ledger_last_time` is the chain close time (seconds); the engine treats it as SYMBOLIC (attacker-
influenceable), so this proves the gate holds for EVERY possible time, not a sampled one. Cliff-style
(time-COMPARISON) release is provable; continuous-linear release (amount = TOT*(now-START)/DUR) is
nonlinear and out of scope (would be INCONCLUSIVE) — real token vesting is cliff + tranches anyway.

Fail-closed (a false PROVEN certifies a Hook that can release early — pre-cliff drain):
  • CLIFF is read from param "CLF" (8B BE seconds). If absent -> N/A (not a timed-release Hook).
  • If the Hook EMITS but never reads ledger_last_time, the emit cannot depend on time -> it can fire
    BEFORE the cliff -> COUNTEREXAMPLE (not a vacuous PROVEN).
  • N/A if no accepting path emits. solver unknown -> INCONCLUSIVE; unsound_gate before any PROVEN.

Usage: python prove_time_release.py <hook.wasm>
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    cliff_b = e.inputs.get("param:CLF")
    if not cliff_b:
        print("— N/A — hook reads no CLF (cliff/unlock-time) param; the time-release property is not "
              "exercised. Not claimed.")
        return 1
    CLIFF = z3.Concat(*cliff_b) if len(cliff_b) > 1 else cliff_b[0]
    if CLIFF.size() < 64:
        CLIFF = z3.ZeroExt(64 - CLIFF.size(), CLIFF)

    now = e.inputs.get("ledger_last_time")   # symbolic 64-bit chain time, or None if never read

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
        if now is None:
            print(f"\n❌ COUNTEREXAMPLE [time-release] — accept code {code} EMITS but the hook never reads "
                  "ledger_last_time: the release cannot depend on time, so it can fire BEFORE the cliff. "
                  "Pre-unlock release is possible.")
            return 2
        nw = now if now.size() == 64 else z3.ZeroExt(64 - now.size(), now)
        s = z3.Solver(); s.set("timeout", 20000)
        s.add(*cons)
        s.add(z3.ULT(nw, CLIFF))             # ...emits while now < CLIFF (before the unlock time)
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [time-release] — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE [time-release] — an accepting path emits BEFORE the cliff/unlock "
                  f"time (accept code {code}): ledger_last_time = {ev(nw)} < CLIFF = {ev(CLIFF)}.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    if n_emit_paths == 0:
        print("— N/A — no accepting path emits a payment; the time-release property is not exercised.")
        return 1

    print("\n✅ PROVEN [time-release] — for ALL inputs, every emitting accept path requires "
          "ledger_last_time >= CLIFF. The Hook releases NOTHING before its unlock/cliff time.")
    print("   SCOPE: cliff (time-comparison) release; continuous-linear amount schedules are nonlinear "
          "and out of scope. Pairs with emit-budget (<=TOT) + emit-dst-lock to certify vesting.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
