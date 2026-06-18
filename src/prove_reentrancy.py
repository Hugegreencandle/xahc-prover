"""Prove SC05 REENTRANCY / cbak-SAFETY — the deferred-accounting + refund-leak invariant.

  for all inputs, given prior committed state with  spent <= LIM  and  reserved <= spent:
    EVERY terminal path of BOTH entry points (`hook` and `cbak`) persists state with
      (cap)   spent'  <= LIM
      (floor) spent'  >= spent - reserved          [cannot net-refund past the reservation]
      (cover) spent'  >= spent + (Σ drops emitted on this path)
                                                    [reserve-before-emit: the spend is recorded
                                                     in the SAME invocation that emits it]

────────────────────────────────────────────────────────────────────────────────
THREAT MODEL — why this is the RIGHT invariant for Hooks (not a blind EVM port)
────────────────────────────────────────────────────────────────────────────────
A Hook may emit() a transaction and later be RE-ENTERED via its `cbak` callback when that
emit settles. But Hook invocations are ATOMIC — `state_set` commits at invocation end, and
`cbak` is a SEPARATE later invocation over already-committed state. So classic EVM mid-call
reentrancy (state read, external call, state write — re-entered before the write) is already
IMPOSSIBLE here. Porting it would be vacuous. The Hook-specific bug class is:

  • DEFERRED ACCOUNTING — the hook emits a spend but records it only in cbak (when the emit
    settles). A 2nd hook() that lands before cbak fires sees stale state and can emit again
    => double-spend past the cap. Caught by (cover): an accepting path emits drops > 0 yet
    persists spent' == prior spent.
  • REFUND LEAK — a settlement cbak refunds MORE than was actually reserved (e.g. wipes the
    whole running spend), so consumed budget escapes the cap. Caught by (floor).

────────────────────────────────────────────────────────────────────────────────
STATE / PARAM CONTRACT (what a hook must look like to be analyzable here)
────────────────────────────────────────────────────────────────────────────────
HookState slot key 0x01, value = 16 bytes big-endian [reserved:u64 | spent:u64]:
  spent    = running cumulative outgoing drops counted against the cap
  reserved = the portion of `spent` still OUTSTANDING (emitted, not yet settled)
Param LIM (8B drops) = cumulative spend cap. The hook is the SPENDING side
(reserve-before-emit); cbak is the SETTLEMENT side (release only the reservation).

INDUCTIVE: with the base case (initial spent = reserved = 0), proving the single-invocation
step for BOTH entry points inductively bounds the cumulative spend across the WHOLE
emit->cbak lifecycle — exactly what a one-shot local sim cannot test (it cannot seed prior
HookState, nor exercise the cbak re-entry).

────────────────────────────────────────────────────────────────────────────────
SCOPE — honest about what a PROVEN does and does NOT mean
────────────────────────────────────────────────────────────────────────────────
IN scope (claimed by PROVEN): the single-invocation inductive step for each entry point —
reserve-before-emit (no deferred accounting) on every accepting/returning path, the cumulative
cap, and the no-refund-leak floor. The engine explores the PRESENT-STATE path (16-byte read,
fresh symbolic prior [reserved|spent]); for cbak it also covers a write-without-read path via
a synthesized symbolic prior.

OUT of scope -> fail closed to INCONCLUSIVE (never PROVEN): unbounded emit/cbak interleaving
depth beyond one step, deep loops past the unroll bound, unsupported opcodes, symbolic-float
over-approximation, an emitted amount the engine could not parse (outflow unbounded), a
persisted value that is not the 16-byte layout. A hook that exports NO cbak -> reported N/A
(exit 1): the reentrancy/cbak surface does not exist, and we never silently call that "safe".

Usage: python prove_reentrancy.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE / fail-closed, 1 = N/A.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate

STATE_KEY = "\x01"   # the fixed 1-byte budget slot key, decoded latin1
W = 128


def z128(x):
    """Zero-extend a bitvec to 128 bits (outflow/spend arithmetic is done wide so a 64-bit
    wrap in the hook's own math cannot produce a false PROVEN)."""
    return z3.ZeroExt(W - x.size(), x) if x.size() < W else x


def _prior(e, tag):
    """The committed prior [reserved|spent] for an engine run. Uses the symbolic value the
    hook READ from slot 0x01; if a path wrote the slot without reading it, synthesize a fresh
    symbolic 16-byte prior (the true unknown prior, universally quantified). Returns
    (reserved_old, spent_old) as 64-bit bitvecs, or None if the read was a non-16-byte layout."""
    old = e.state_old.get(STATE_KEY)
    if old is None:
        old = [z3.BitVec(f"{tag}_prior_{i}", 8) for i in range(16)]
    if len(old) != 16:
        return None
    return z3.Concat(*old[0:8]), z3.Concat(*old[8:16])


def _gather(e):
    """All terminal paths of an engine run as (cons, writes, emits): accepting paths
    (hook) AND normal-return paths (cbak settles + returns without accept/rollback)."""
    out = []
    for (code, cons, writes), (_c2, emits, _ec) in zip(e.accepts_full, e.emits_on_accept):
        out.append((cons, writes, emits))
    for (cons, writes, emits, _ec) in e.returns_full:
        out.append((cons, writes, emits))
    return out


def _eff_spent_reserved(writes, reserved_old, spent_old):
    """Effective persisted (reserved', spent') for a path. If the slot is written, decode the
    128-bit value (high 8B = reserved', low 8B = spent'); else the committed value is unchanged.
    Returns (reserved', spent', err) where err is a message if the write is not 16 bytes."""
    if STATE_KEY in writes:
        wval = writes[STATE_KEY]
        if wval.size() != 128:
            return None, None, f"persisted value is {wval.size() // 8}B, not the 16B [reserved|spent] layout"
        return z3.Extract(127, 64, wval), z3.Extract(63, 0, wval), None
    return reserved_old, spent_old, None


def _check_entry(label, e, lim):
    """Run the three obligations over every terminal path of one entry. Returns an exit code
    if a verdict is reached (2 / 3), or None to continue."""
    pr = _prior(e, label)
    if pr is None:
        print(f"\n⚠️ INCONCLUSIVE [{label}] — prior state read is not the 16-byte "
              "[reserved|spent] layout; cannot decode. Not PROVEN.")
        return 3
    reserved_old, spent_old = pr
    # Inductive hypothesis: the prior committed state is in-budget AND well-formed
    # (the outstanding reservation is part of the counted spend).
    hyp = z3.And(z3.ULE(spent_old, lim), z3.ULE(reserved_old, spent_old))

    paths = _gather(e)
    print(f"explored [{label}]: {len(paths)} terminal path(s)")

    for cons, writes, emits in paths:
        if not feasible(cons):
            continue
        new_reserved, new_spent, err = _eff_spent_reserved(writes, reserved_old, spent_old)
        if err:
            print(f"\n⚠️ INCONCLUSIVE [{label}] — {err}. Not PROVEN.")
            return 3

        # (cap) accept/return ⟹ spent' <= LIM
        s = z3.Solver(); s.set("timeout", 120000)
        s.add(*cons); s.add(hyp); s.add(z3.UGT(new_spent, lim))
        r = s.check()
        if r == z3.unknown:
            print(f"\n⚠️ INCONCLUSIVE [{label}/cap] — solver `unknown`; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print(f"\n❌ COUNTEREXAMPLE [{label}/cap] — an in-budget prior is driven OVER the cap:")
            print(f"   prior spent={ev(spent_old)} reserved={ev(reserved_old)} LIM={ev(lim)}")
            print(f"   persisted spent'={ev(new_spent)} > LIM")
            return 2

        # (well-formed) spent' >= reserved'  — CLOSES THE INDUCTION. The hypothesis assumes the
        # prior is well-formed (reserved_old <= spent_old, line `hyp`); for the inductive step to
        # be sound, every path must RE-ESTABLISH that on the persisted state, else a reachable
        # post-state with reserved' > spent' is excluded from the next step's hypothesis AND from
        # cbak's prior — and a release-only cbak (spent' = spent - reserved, clamped >=0) then
        # wipes spend to 0, letting cumulative outflow exceed LIM across emit->cbak. Without this
        # check the PROVEN does NOT bound cumulative spend (audit REENTRANCY-01, false-PROVEN).
        s = z3.Solver(); s.set("timeout", 120000)
        s.add(*cons); s.add(hyp)
        s.add(z3.UGT(z128(new_reserved), z128(new_spent)))   # persists reserved' > spent'
        r = s.check()
        if r == z3.unknown:
            print(f"\n⚠️ INCONCLUSIVE [{label}/well-formed] — solver `unknown`; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print(f"\n❌ COUNTEREXAMPLE [{label}/unclosed-induction] — persists a malformed state "
                  "(reserved' > spent') the proof's own hypothesis excludes:")
            print(f"   persisted reserved'={ev(new_reserved)} > spent'={ev(new_spent)} -> a "
                  "release-only cbak can then wipe spend to 0, so cumulative outflow can exceed LIM")
            return 2

        # (floor) spent' >= spent - reserved  (cannot net-refund past the reservation)
        s = z3.Solver(); s.set("timeout", 120000)
        s.add(*cons); s.add(hyp)
        s.add(z3.ULT(z128(new_spent), z128(spent_old) - z128(reserved_old)))
        r = s.check()
        if r == z3.unknown:
            print(f"\n⚠️ INCONCLUSIVE [{label}/floor] — solver `unknown`; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print(f"\n❌ COUNTEREXAMPLE [{label}/refund-leak] — refunds past the reservation:")
            print(f"   prior spent={ev(spent_old)} reserved={ev(reserved_old)}  "
                  f"floor=spent-reserved={ev(spent_old) - ev(reserved_old)}")
            print(f"   persisted spent'={ev(new_spent)} < floor -> budget escapes the cap")
            return 2

        # (cover) reserve-before-emit: spent' >= spent + Σ emitted drops on this path.
        # Only meaningful when the path actually emits; an unparsed emit -> fail closed.
        if emits:
            if any(x is None for x in emits):
                print(f"\n⚠️ INCONCLUSIVE [{label}/cover] — an emitted amount could not be "
                      "parsed (non-template payment); outflow unbounded, cannot verify "
                      "reserve-before-emit. Not PROVEN.")
                return 3
            outflow = z3.BitVecVal(0, W)
            for x in emits:
                outflow = outflow + z128(x)
            s = z3.Solver(); s.set("timeout", 120000)
            s.add(*cons); s.add(hyp)
            s.add(z3.ULT(z128(new_spent), z128(spent_old) + outflow))
            r = s.check()
            if r == z3.unknown:
                print(f"\n⚠️ INCONCLUSIVE [{label}/cover] — solver `unknown`; not PROVEN.")
                return 3
            if r == z3.sat:
                m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
                print(f"\n❌ COUNTEREXAMPLE [{label}/deferred-accounting] — emits without "
                      "reserving in the same invocation:")
                print(f"   prior spent={ev(spent_old)}  emitted Σ={ev(outflow)} drops")
                print(f"   persisted spent'={ev(new_spent)} < spent+emitted="
                      f"{ev(spent_old) + ev(outflow)} -> spend deferred (re-entry double-spend)")
                return 2
    return None


def _gates(label, e):
    """Standard fail-closed gates for one engine run (must precede any PROVEN)."""
    code = unsound_gate(e)
    if code is not None:
        return code
    return None


def main(path: str) -> int:
    wasm = open(path, "rb").read()

    # --- run the HOOK entry ---
    e1 = Engine(wasm)
    e1.run()

    # N/A: no cbak export -> the reentrancy/cbak surface does not exist. Never silently "safe".
    if not e1.has_cbak:
        print("N/A — the module exports no `cbak` callback, so there is no emit->settlement "
              "re-entry surface to analyze. (Not a reentrancy claim either way.)")
        return 1

    # The stateful PERIOD-BUDGET contract also uses a 16-byte slot 0x01, but as
    # [periodStart|spent] (marked by reading PLM/PER) — a DIFFERENT layout this driver would
    # misread. Defer it to prove_period_budget rather than emit a misleading verdict.
    if e1.inputs.get("param:PLM") or e1.inputs.get("param:PER"):
        print("N/A — this hook reads PLM/PER, i.e. the stateful PERIOD-BUDGET contract (slot "
              "0x01 = [periodStart|spent]); analyze it with `--invariant period-budget`. The "
              "reentrancy driver targets the reserve-before-emit contract (slot 0x01 = "
              "[reserved|spent]).")
        return 1

    lim_bytes = e1.inputs.get("param:LIM")
    if not lim_bytes:
        print("ERROR: hook does not read a `LIM` (8-byte cumulative-cap) HookParameter; this "
              "driver expects the reserve-before-emit budget contract (slot 0x01 = "
              "[reserved:u64|spent:u64], param LIM). Not analyzable.")
        return 1
    lim_hook = z3.Concat(*lim_bytes)   # 64-bit cumulative cap the hook actually read

    rc = _check_entry("hook", e1, lim_hook)
    if rc is not None:
        return rc

    # --- run the CBAK entry (the re-entry surface) on a fresh engine ---
    e2 = Engine(wasm)
    e2.run(e2.cbak)
    # cbak need not read LIM; the cap bound is universally quantified over a fresh LIM (a
    # release-only cbak keeps spent' <= spent_old <= LIM for ANY LIM under the hypothesis).
    lim_cbak = z3.BitVec("REENTRANCY_LIM_cbak", 64)
    rc = _check_entry("cbak", e2, lim_cbak)
    if rc is not None:
        return rc

    # --- fail-closed gates for BOTH runs, BEFORE any PROVEN ---
    for label, e in (("hook", e1), ("cbak", e2)):
        rc = _gates(label, e)
        if rc is not None:
            return rc

    print("\n✅ PROVEN [reentrancy / cbak-safety, INDUCTIVE STEP] — for ALL inputs, IF the "
          "prior committed state satisfies spent <= LIM and reserved <= spent, THEN every "
          "terminal path of BOTH `hook` and `cbak` persists state that:")
    print("   • stays within the cumulative cap   (spent' <= LIM)")
    print("   • never refunds past the reservation (spent' >= spent - reserved)")
    print("   • records every emitted spend up front (spent' >= spent + Σ emitted) — "
          "reserve-before-emit, no deferred accounting.")
    print("   SCOPE: single-invocation inductive step per entry point; combined with the "
          "spent=reserved=0 base case this bounds the cumulative spend across the whole "
          "emit->cbak lifecycle. Out-of-scope cases fail closed to INCONCLUSIVE — see docstring.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
