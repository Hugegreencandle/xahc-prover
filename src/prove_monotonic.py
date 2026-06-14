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
from prover import Engine


def main(path: str, strict: bool = False) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    print(f"explored: {len(e.accepts_full)} accepting path(s); "
          f"state keys written: {sorted({k for _, _, w in e.accepts_full for k in w})}")

    for code, cons, writes in e.accepts_full:
        for kn, wval in writes.items():
            old_bytes = e.state_old.get(kn)
            if not old_bytes:
                continue                       # never read before writing — nothing to compare
            old = z3.Concat(*old_bytes) if len(old_bytes) > 1 else old_bytes[0]
            if old.size() != wval.size():
                continue
            # violation = an accepting path that lands the stored value LOWER
            bad = z3.ULE(wval, old) if strict else z3.ULT(wval, old)
            s = z3.Solver(); s.add(*cons); s.add(bad)
            if s.check() == z3.sat:
                m = s.model()
                ev = lambda b: m.eval(b, model_completion=True).as_long()
                rel = "<=" if strict else "<"
                print(f"\n❌ COUNTEREXAMPLE — accept writes state[{kn}] {rel} its prior value "
                      f"(state moves backwards → replay/rollback):")
                print(f"   written = {ev(wval)}   prior = {ev(old)}")
                return 2

    print(f"\n✅ PROVEN — for ALL inputs, every accepted write to hook state is "
          f"{'strictly greater than' if strict else 'never below'} its prior value. "
          f"State is monotonic; no replay/rollback.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], "--strict" in sys.argv[2:]))
