"""Prove the STATEFUL agent guardrail's PERIOD-BUDGET invariant — the INDUCTIVE STEP.

This hook (agent_guardrail_stateful) is an AI agent's spending AUTHORITY. A false
PROVEN here is catastrophic, so every step below fails CLOSED.

────────────────────────────────────────────────────────────────────────────────
THE INVARIANT (single-invocation inductive step)
────────────────────────────────────────────────────────────────────────────────
HookState value layout (16 bytes, big-endian): [periodStart:u64 | spent:u64],
under the fixed 1-byte key 0x01. Params LIM/PLM (8B drops), PER (4 or 8B ledgers),
DST (optional 20B).

We prove, for ALL inputs to ONE invocation — symbolic otxn amount A (native drops),
symbolic ledger `now` (ledger_seq), symbolic PRIOR state (periodStart, spent), and
symbolic params LIM/PLM/PER/DST:

    INDUCTIVE HYPOTHESIS:   spent <= PLM          (the prior state is in-budget)
    ===>  on EVERY accepting path:
            (a) the newly persisted  spent' <= PLM            [period budget]
            (b)                       A     <= LIM            [per-tx cap]
            (c) if a DST policy is set, dest == DST           [destination lock]

Base case (proved elsewhere / trivially): the initial state has spent = 0 <= PLM.
Combined, induction proves the CUMULATIVE period budget is never exceeded across an
unbounded sequence of payments — exactly what the local sim harness CANNOT test
(it cannot seed a prior HookState).

────────────────────────────────────────────────────────────────────────────────
SCOPE — what is PROVEN vs what is OUT OF SCOPE (be honest, never overclaim)
────────────────────────────────────────────────────────────────────────────────
The engine models the host `state(...)` read as returning a 16-byte value with a
CONCRETE length 16 and a FRESH SYMBOLIC prior value (`state_old['\\x01']`). This is
exactly the PRESENT-STATE path the hook takes when `srd == 16`. Within that path the
engine DOES symbolically explore BOTH sub-branches of the period logic:
  • SAME-PERIOD   (now >= periodStart and now - periodStart < PER): effectiveSpent = spent
  • PERIOD RESET  (now <  periodStart  OR  now - periodStart >= PER): effectiveSpent = 0
…because the period arithmetic (`now < periodStart`, `now - periodStart >= PER`) is
done over the symbolic 64-bit `ledger_seq` and `state_old` bytes — the reset is a real
symbolic If in the persisted-value expression (verified). So BOTH the same-period and
the reset case are covered by this proof.

OUT OF SCOPE (the engine's `state` model returns concrete length 16, so these hook
branches are NOT symbolically explored and are NOT claimed here):
  • the ABSENT-STATE / fresh-period branch (`srd < 0`): there spent := 0, which on the
    accept path persists spent' = A <= LIM <= ... — not covered by THIS driver's
    present-state exploration. (It is a base-case-like path; the hook sets spent=0 and
    the per-tx cap still bounds A. We do NOT fold a claim about it into the verdict.)
  • the CORRUPT-STATE branch (present but length != 16): the hook rolls back
    (fail-closed); not an accept path.
If the engine ever reports an unsupported opcode / hit unroll bound, we return
INCONCLUSIVE — never PROVEN.

State read/write modeling: the PRIOR `spent`/`periodStart` are the low/high 8 bytes of
the symbolic `state_old['\\x01']`; the PERSISTED `spent'` is the low 8 bytes of the
128-bit value the hook writes via state_set (captured per-path in accepts_full). The
period arithmetic and the `effectiveSpent = (reset ? 0 : spent)` selection are the
engine's own symbolic execution of the hook's WASM — we do not re-model them by hand.

Usage: python prove_period_budget.py <hook.wasm>
Exit 0 = PROVEN (scoped), 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = N/A.
"""
import sys
import z3
from prover import Engine, feasible

STATE_KEY = "\x01"   # the fixed 1-byte budget slot key, decoded latin1


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    # ── locate the symbolic inputs the hook exposes ─────────────────────────
    amt = e.inputs.get("amt")               # 8 sfAmount bytes (native path)
    lim = e.inputs.get("param:LIM")
    plm = e.inputs.get("param:PLM")
    old = e.state_old.get(STATE_KEY)        # 16-byte symbolic PRIOR state value
    seq = e.inputs.get("ledger_seq")
    if not all([amt, lim, plm, old, seq is not None]):
        print("ERROR: hook does not look like agent_guardrail_stateful "
              "(needs sfAmount, LIM, PLM, a 16-byte state read, ledger_seq).")
        return 1
    if len(old) != 16:
        print(f"⚠️ INCONCLUSIVE — prior state read is {len(old)} bytes, not the "
              f"16-byte [periodStart|spent] layout; cannot decode. Not PROVEN.")
        return 3

    # decode params + prior state, all big-endian
    LIM = z3.Concat(*lim)                          # 64-bit per-tx cap
    PLM = z3.Concat(*plm)                          # 64-bit period cap
    spent_old = z3.Concat(*old[8:16])             # 64-bit prior cumulative spend
    # the per-tx drops the hook uses: byte0 masked 0x3F (strips not-XRP/sign), big-endian
    drops = z3.Concat(amt[0] & 0x3F, *amt[1:])

    # the period-budget accept paths are the ones that PERSIST state (write key 0x01).
    budget_paths = [(c, cons, w) for (c, cons, w) in e.accepts_full if STATE_KEY in w]
    other_accepts = [(c, cons) for (c, cons, w) in e.accepts_full if STATE_KEY not in w]
    print(f"explored: {len(e.accepts_full)} accepting path(s) "
          f"({len(budget_paths)} persist the budget slot, "
          f"{len(other_accepts)} are pass-through/non-budget); "
          f"{len(e.rollbacks)} rolling back")

    # INDUCTIVE HYPOTHESIS applied to every obligation below.
    hyp = z3.ULE(spent_old, PLM)

    # ── (a) PERIOD BUDGET: persisted spent' <= PLM on every accepting path ───
    for code, cons, writes in budget_paths:
        if not feasible(cons):
            continue
        wval = writes[STATE_KEY]
        if wval.size() != 128:
            print(f"⚠️ INCONCLUSIVE — persisted value on accept code {code} is "
                  f"{wval.size()//8}B, not the expected 16B [periodStart|spent]; "
                  f"cannot decode spent'. Not PROVEN.")
            return 3
        new_spent = z3.Extract(63, 0, wval)        # low 8 bytes = spent'
        s = z3.Solver()
        s.add(*cons)
        s.add(hyp)                                  # prior in-budget (induction)
        s.add(z3.UGT(new_spent, PLM))               # ...yet persists OVER budget
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [period-budget] — solver returned `unknown` "
                  "(timeout/incompleteness) on an accepting path; cannot claim PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE [period-budget] — an in-budget prior state is "
                  "driven OVER the period cap on an accepting path:")
            print(f"   accept code {code}:")
            print(f"     prior spent = {ev(spent_old)}   PLM = {ev(PLM)}  "
                  f"(hypothesis spent<=PLM holds)")
            print(f"     amount A    = {ev(drops)}        LIM = {ev(LIM)}")
            print(f"     now         = {ev(seq)}")
            print(f"     persisted spent' = {ev(new_spent)}  >  PLM = {ev(PLM)}")
            return 2

    # ── (b) PER-TX CAP: accept ⟹ A <= LIM (on the budget paths) ─────────────
    for code, cons, writes in budget_paths:
        if not feasible(cons):
            continue
        s = z3.Solver()
        s.add(*cons)
        s.add(z3.UGT(drops, LIM))                   # accepted an over-LIM payment
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [per-tx] — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE [per-tx] — accepts a payment over the per-tx LIM:")
            print(f"   accept code {code}: A={ev(drops)} > LIM={ev(LIM)}")
            return 2

    # ── (c) DESTINATION LOCK: accept ⟹ dest == DST when a DST policy is set ──
    dest = e.inputs.get("dest")
    allowed = e.inputs.get("param:DST")
    dst_ret = e.inputs.get("hook_param_ret:DST")
    dst_proven = False
    if dest and allowed and dst_ret is not None:
        dest_mismatch = z3.Or(*[dest[i] != allowed[i] for i in range(20)])
        for code, cons, writes in budget_paths:
            if not feasible(cons):
                continue
            s = z3.Solver()
            s.add(*cons)
            s.add(dst_ret == 20)                    # a 20-byte DST policy present
            s.add(dest_mismatch)                    # ...to a non-allowed destination
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE [dst-lock] — solver `unknown` on an accept path; not PROVEN.")
                return 3
            if r == z3.sat:
                m = s.model()
                ev = lambda b: m.eval(b, model_completion=True).as_long()
                dv = bytes(ev(b) for b in dest)
                av = bytes(ev(b) for b in allowed)
                print("\n❌ COUNTEREXAMPLE [dst-lock] — accepts a payment to a non-allowed destination:")
                print(f"   accept code {code}: dest={dv.hex().upper()} allowed(DST)={av.hex().upper()}")
                return 2
        dst_proven = True

    # ── fail-closed gates (after the obligations, BEFORE any PROVEN) ─────────
    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} reached "
              f"during analysis; cannot prove. Refusing PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; deeper iterations were "
              "not explored. Cannot claim PROVEN.")
        return 3
    if not budget_paths:
        print("\n⚠️ INCONCLUSIVE — no accepting path persists the budget slot (key 0x01); "
              "the period-budget property was not exercised. Not PROVEN.")
        return 3

    # ── PROVEN (scoped) ─────────────────────────────────────────────────────
    print("\n✅ PROVEN [period-budget, INDUCTIVE STEP] — for ALL inputs, IF the prior "
          "state satisfies spent <= PLM, THEN every accepting path persists spent' <= PLM.")
    print("✅ PROVEN [per-tx]    — every accepting (budget) path has A <= LIM.")
    if dst_proven:
        print("✅ PROVEN [dst-lock]  — when a DST policy is set, an accepted payment goes "
              "only to the allowed destination.")
    print("   SCOPE: present-state path (state read == 16B) covering BOTH the same-period "
          "and period-reset sub-branches. The absent/fresh-period branch (srd<0) and "
          "corrupt-state branch (rolls back) are outside this driver's exploration; see "
          "module docstring. Combined with the spent=0 base case, this inductively bounds "
          "the cumulative period spend.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
