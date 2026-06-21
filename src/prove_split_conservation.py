"""Prove SPLIT-CONSERVATION: a distribution Hook pays out EXACTLY the declared total — no skim, no short.

The invariant behind a revenue-share / royalty / payroll-split Hook: when it distributes a period total
PER across N beneficiaries, the sum of what it emits must equal PER exactly — it can't quietly keep a
cut (skim) or short a beneficiary. We prove, for ALL inputs:

    accept-with-emit  =>  SUM(emitted native drops this fire)  ==  PER     (param "PER", 8B BE)

Computed at 128-bit width so a multi-emit sum can't wrap. Generalizes: 1 emit (== PER) or N emits
(summing to PER) both conserve. Pairs with emit-budget (cumulative <= CAP) + trigger-lock to certify a
scheduled distributor.

Fail-closed (a false PROVEN certifies a Hook that can skim funds — silent theft):
  • PER absent -> N/A (not a declared-total distributor).
  • If ANY emitted txn's drops is unparseable (None) on a checked path -> INCONCLUSIVE (can't sum it;
    IOU emits are out of scope here).
  • N/A if no accepting path emits. solver unknown -> INCONCLUSIVE; unsound_gate before any PROVEN.

Usage: python prove_split_conservation.py <hook.wasm>
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate

W = 128


def _w(bv):
    return z3.ZeroExt(W - bv.size(), bv) if bv.size() < W else bv


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    per_b = e.inputs.get("param:PER")
    if not per_b:
        print("— N/A — hook reads no PER (per-fire distribution total) param; the split-conservation "
              "property is not exercised. Not claimed.")
        return 1
    PER = _w(z3.Concat(*per_b) if len(per_b) > 1 else per_b[0])

    n = len(e.accepts_full)
    if len(e.emits_on_accept) != n:
        print("\n⚠️ INCONCLUSIVE — accept/emit path lists are not aligned; refusing PROVEN.")
        return 3

    n_emit_paths = 0
    for i in range(n):
        code, cons, _writes = e.accepts_full[i]
        _, emits, emit_count = e.emits_on_accept[i]
        if not feasible(cons):
            continue
        if emit_count == 0 or not emits:
            continue
        if any(em is None for em in emits):
            print(f"\n⚠️ INCONCLUSIVE [split-conservation] — accept code {code} emits a txn whose drops the "
                  "engine could not parse; cannot sum the distribution. Not PROVEN.")
            return 3
        n_emit_paths += 1
        # SOUNDNESS: the engine records emit drops MASKED to the native-amount encoding (top 2 type
        # bits cleared) — masked == real ONLY for amounts < 2^62. The equality `sum == PER` over masked
        # values is therefore trustworthy ONLY when the target is a valid native amount. If the hook
        # doesn't provably bound PER < 2^62, a >=2^62 emit could mask-collide to PER -> fail CLOSED
        # rather than risk certifying a skim/over-distribute. (Emitted SHARES are < 2^62 by the protocol's
        # native-amount validity, which it enforces on-ledger — stated in SCOPE.)
        rng = z3.Solver(); rng.set("timeout", 20000)
        rng.add(*cons); rng.add(z3.UGE(PER, z3.BitVecVal(1 << 62, W)))
        if rng.check() != z3.unsat:
            print("\n⚠️ INCONCLUSIVE [split-conservation] — the declared total PER is not provably "
                  "< 2^62 (a valid native amount); the encoding-masked emit sum cannot be soundly "
                  "compared. The hook must bound its amounts. Not PROVEN.")
            return 3
        total = z3.BitVecVal(0, W)
        for em in emits:
            total = total + _w(em)
        s = z3.Solver(); s.set("timeout", 20000)
        s.add(*cons)
        s.add(total != PER)                  # ...the sum distributed is NOT exactly the declared total
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [split-conservation] — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            tv, pv = ev(total), ev(PER)
            kind = "SKIMS (keeps a cut)" if tv < pv else "OVER-DISTRIBUTES"
            print("\n❌ COUNTEREXAMPLE [split-conservation] — an accepting path does NOT distribute the "
                  f"exact declared total (accept code {code}): emitted sum = {tv}, declared PER = {pv} "
                  f"-> the Hook {kind}.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    if n_emit_paths == 0:
        print("— N/A — no accepting path emits a payment; the split-conservation property is not exercised.")
        return 1

    print("\n✅ PROVEN [split-conservation] — for ALL inputs, every emitting accept path distributes "
          "EXACTLY the declared total PER (sum of emitted drops == PER). The Hook cannot skim a cut or "
          "short a beneficiary.")
    print("   SCOPE: native (XAH) emits, with PER provably < 2^62 (a valid native amount) and each emitted "
          "share < 2^62 by the protocol's on-ledger native-amount validity (max ~1e17 drops). An IOU/"
          "unparseable emit, or a PER not provably < 2^62, fails closed. Pairs with emit-budget + trigger-lock.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
