"""Prove STATE-MONOTONICITY — a persisted value never moves backwards.

  for all inputs:  accept  =>  value written to state key K  >=  value read from K

The canonical use is replay protection: a stored nonce / sequence / high-water mark
that must only ever increase. A hook that can be driven to overwrite it with a
SMALLER value is a replay or rollback vulnerability. The engine models `state`
(returns a symbolic prior value — the adversarial case: the slot already holds
something) and `state_set` (records the written value per path); this driver checks
no accepting path writes a value below what it read.

Usage: python prove_monotonic.py <hook.wasm> [--strict]
  --strict : require STRICTLY increasing (written > old); default is non-decreasing.
"""
import sys
import z3
from prover import Engine, feasible


def main(path: str, strict: bool = False) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    print(f"explored: {len(e.accepts_full)} accepting path(s); "
          f"state keys written: {sorted({k for _, _, w in e.accepts_full for k in w})}")

    for code, cons, writes in e.accepts_full:
        # only consider paths that are actually reachable
        if not feasible(cons):
            continue
        for kn, wval in writes.items():
            old_bytes = e.state_old.get(kn)
            # SOUND: a write to a key that was NEVER read on any path means the
            # hook overwrites persisted state with NO regard for its prior value —
            # i.e. an unconditional `state_set(NONCE, attacker_value)`. That is the
            # canonical replay/rollback bug, NOT a safe case. Treat it as a
            # COUNTEREXAMPLE (state can move backwards because nothing constrains it
            # to the prior value). NEVER silently skip it (the old bug emitted a
            # vacuous PROVEN here).
            if not old_bytes:
                print(f"\n❌ COUNTEREXAMPLE — accept writes state[{kn}] WITHOUT ever "
                      f"reading it (no prior-value comparison constrains the write):")
                print(f"   the stored value is overwritten unconditionally → an "
                      f"attacker-supplied (possibly smaller/replayed) value is "
                      f"accepted. State is NOT monotonic.")
                return 2
            old = z3.Concat(*old_bytes) if len(old_bytes) > 1 else old_bytes[0]
            if old.size() != wval.size():
                # A width mismatch means we CANNOT compare the written value to the
                # prior value, so monotonicity is unproven for this write. Refuse to
                # claim PROVEN — report INCONCLUSIVE rather than silently passing.
                print(f"\n⚠️ INCONCLUSIVE — accept writes state[{kn}] with a byte-width "
                      f"({wval.size() // 8}B) different from what it read "
                      f"({old.size() // 8}B); the written and prior values are not "
                      f"comparable, so monotonicity cannot be proven. Not a PROVEN pass.")
                return 3
            # violation = an accepting path that lands the stored value LOWER
            bad = z3.ULE(wval, old) if strict else z3.ULT(wval, old)
            s = z3.Solver(); s.add(*cons); s.add(bad)
            r = s.check()
            if r == z3.sat:
                m = s.model()
                ev = lambda b: m.eval(b, model_completion=True).as_long()
                rel = "<=" if strict else "<"
                print(f"\n❌ COUNTEREXAMPLE — accept writes state[{kn}] {rel} its prior value "
                      f"(state moves backwards → replay/rollback):")
                print(f"   written = {ev(wval)}   prior = {ev(old)}")
                return 2
            if r == z3.unknown:
                # SOUND: Z3 could not decide (timeout/incompleteness). `unknown` is
                # NOT "no counterexample" — refuse to claim PROVEN.
                print(f"\n⚠️ INCONCLUSIVE — the solver returned `unknown` checking "
                      f"monotonicity of state[{kn}] (timeout/incompleteness). "
                      f"Cannot claim PROVEN.")
                return 3

    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} "
              f"(e.g. br_table / call_indirect) reached during analysis; cannot prove "
              f"monotonicity. Refusing to claim PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; deeper iterations "
              "were not explored. Cannot claim PROVEN.")
        return 3

    print(f"\n✅ PROVEN — for ALL inputs, every accepted write to hook state is "
          f"{'strictly greater than' if strict else 'never below'} its prior value. "
          f"State is monotonic; no replay/rollback.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], "--strict" in sys.argv[2:]))
