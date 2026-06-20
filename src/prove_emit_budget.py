"""Prove the EMIT-BUDGET invariant — the first invariant over a Hook's OUTGOING autonomous spend.

Gate-model invariants (period-budget/dst-lock/conservation) police an otxn the agent tries to make,
via accept/rollback. AUTONOMOUS primitives (Cron-fired subscriptions, vesting, DCA, streaming) instead
EMIT payments — there is no otxn to gate. This driver proves the cumulative emitted spend is bounded,
which is the core safety property of an unattended money-mover (and unattended + weak-TSH = no rollback,
so it MUST be proven, not trusted — see docs/CRON-GROUND-TRUTH.md).

THE INVARIANT (single-invocation inductive step). State slot 0x01 holds an 8-byte big-endian `paid`
(cumulative drops emitted). Param "CAP" (8B BE) = the lifetime cap. For ALL inputs to ONE invocation,
with symbolic prior `paid` and symbolic params, on EVERY accepting path:

    INDUCTIVE HYPOTHESIS:  paid <= CAP                              (prior state in-budget)
    ===>  (C1 no-overspend)  paid + Σ(emitted drops this path) <= CAP
          (C2 honest-record) the persisted paid' >= paid + Σ(emitted drops this path)

C1 says a fire never emits past the remaining budget. C2 says the counter is advanced by AT LEAST what
was emitted (no emit-then-under-record that would re-open budget next fire). Together, by induction over
the unbounded sequence of fires (base case paid=0 <= CAP), the CUMULATIVE emitted spend never exceeds CAP.

SCOPE / fail-closed (a false PROVEN certifies a money-drainer — every step fails closed):
  • Native (XAH) emits only. If ANY emitted txn's drops is unparseable (None) on a checked path, we
    CANNOT bound the spend -> INCONCLUSIVE. IOU emits are not covered here (would be emit-budget-iou).
  • C2 is checked only on paths that PERSIST slot 0x01; a path that emits but writes no counter fails C2
    trivially (new_paid is absent) -> reported as a counterexample (it emitted without recording).
  • N/A if the hook reads no CAP param or never emits (the property isn't exercised).
  • Sums are computed at 128-bit width (paid<=2^64, a few emits each <2^64) so the bound check can't wrap.
  • unsound_gate (float over-approx / unsupported op / hit bound) runs BEFORE any PROVEN.

Usage: python prove_emit_budget.py <hook.wasm>
Exit 0 PROVEN (scoped) · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate

STATE_KEY = "\x01"
W = 128  # sum width — paid (<=2^64) + a handful of emits (each <2^64) cannot overflow 128 bits


def _w(bv):
    return z3.ZeroExt(W - bv.size(), bv) if bv.size() < W else bv


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    cap_b = e.inputs.get("param:CAP")
    paid_old_bytes = e.state_old.get(STATE_KEY)
    if not cap_b:
        print("— N/A — hook reads no CAP param; the emit-budget property is not exercised. Not claimed.")
        return 1
    if STATE_KEY in e.state_old_overwritten:
        print("\n⚠️ INCONCLUSIVE — the budget slot was read at inconsistent byte-widths (ambiguous prior "
              "model); refusing PROVEN (fail closed).")
        return 3
    if not paid_old_bytes:
        print("— N/A — hook never reads the cumulative-paid state slot (0x01); not an emit-budget hook.")
        return 1

    CAP = _w(z3.Concat(*cap_b)) if len(cap_b) > 1 else _w(cap_b[0])
    paid_old = _w(z3.Concat(*paid_old_bytes[:8])) if len(paid_old_bytes) >= 8 else _w(z3.Concat(*paid_old_bytes))
    hyp = z3.ULE(paid_old, CAP)   # inductive hypothesis: prior state in-budget

    # index-aligned per-accepting-path views (appended together in the engine's accept handler)
    n = len(e.accepts_full)
    if len(e.emits_on_accept) != n:
        print("\n⚠️ INCONCLUSIVE — accept/emit path lists are not aligned; refusing PROVEN.")
        return 3

    n_emit_paths = 0
    for i in range(n):
        code, cons, writes = e.accepts_full[i]
        _, emits, emit_count = e.emits_on_accept[i]
        if not feasible(cons):
            continue
        # this path's emitted native drops
        if emit_count == 0 or not emits:
            continue                              # no emit -> trivially within budget; nothing to check
        if any(em is None for em in emits):
            print(f"\n⚠️ INCONCLUSIVE [emit-budget] — accept code {code} emits a txn whose drops the "
                  "engine could not parse; cannot bound the spend. Not PROVEN.")
            return 3
        n_emit_paths += 1
        spend = z3.BitVecVal(0, W)
        for em in emits:
            spend = spend + _w(em)

        # ── C1: no-overspend — paid + spend must stay within CAP ───────────────
        s = z3.Solver(); s.set("timeout", 20000)
        s.add(*cons); s.add(hyp)
        s.add(z3.UGT(paid_old + spend, CAP))      # ...yet this fire pushes cumulative over CAP
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [emit-budget/C1] — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE [emit-budget] — an in-budget prior state is driven OVER the cap by "
                  f"emitted spend on accept code {code}:")
            print(f"     prior paid = {ev(paid_old)}   CAP = {ev(CAP)}   emitted this fire = {ev(spend)}")
            print(f"     paid + emitted = {ev(paid_old + spend)}  >  CAP = {ev(CAP)}")
            return 2

        # ── C2: honest-record — persisted paid' >= paid + spend ────────────────
        if STATE_KEY not in writes:
            print("\n❌ COUNTEREXAMPLE [emit-budget] — accept code "
                  f"{code} EMITS but persists no cumulative-paid counter (slot 0x01): the spend is not "
                  "recorded, so the next fire re-opens the full budget (unbounded cumulative spend).")
            return 2
        wval = writes[STATE_KEY]
        new_paid = _w(z3.Extract(63, 0, wval) if wval.size() >= 64 else wval)
        s2 = z3.Solver(); s2.set("timeout", 20000)
        s2.add(*cons); s2.add(hyp)
        s2.add(z3.ULT(new_paid, paid_old + spend))   # persisted LESS than prior+emitted
        r2 = s2.check()
        if r2 == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [emit-budget/C2] — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r2 == z3.sat:
            m = s2.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE [emit-budget] — emitted spend is UNDER-recorded on accept code "
                  f"{code} (budget re-opens next fire):")
            print(f"     prior paid = {ev(paid_old)}  emitted = {ev(spend)}  persisted paid' = {ev(new_paid)}")
            print(f"     paid' = {ev(new_paid)}  <  paid + emitted = {ev(paid_old + spend)}")
            return 2

    # ── fail-closed gates BEFORE any PROVEN ──────────────────────────────────
    code = unsound_gate(e)
    if code is not None:
        return code
    if n_emit_paths == 0:
        print("— N/A — no accepting path emits a payment; the emit-budget property is not exercised.")
        return 1

    print("\n✅ PROVEN [emit-budget, INDUCTIVE STEP] — for ALL inputs, IF prior paid <= CAP, THEN every "
          "emitting path keeps paid + Σemitted <= CAP (no overspend) AND persists paid' >= paid + Σemitted "
          "(honest record). With the paid=0 base case, the CUMULATIVE emitted spend never exceeds CAP.")
    print("   SCOPE: native (XAH) emits; present-state path (slot 0x01 read). IOU emits + absent-state "
          "branch out of scope. The first invariant over a Hook's OUTGOING autonomous spend.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
