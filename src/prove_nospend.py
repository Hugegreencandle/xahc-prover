"""Prove NO-DOUBLE-SPEND — a hook emits at most N payments per invocation.

  for all inputs:  accept  =>  number of emitted txns  <=  MAX   (default 1)

A hook that can be driven to emit more payments than its policy allows lets an
attacker trigger multiple payouts from one transaction. The engine counts emit()
calls per path (loops are unrolled, so the count is exact); this driver flags any
accepting path that emits more than MAX.

Usage: python prove_nospend.py <hook.wasm> [MAX]
"""
import sys
from prover import Engine, feasible


def main(path: str, max_emits: int = 1) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    counts = sorted({c for _, _, c in e.emits_on_accept})
    print(f"explored: {len(e.emits_on_accept)} accepting path(s); emit counts seen: {counts}")

    for cons, _emits, count in e.emits_on_accept:
        if count > max_emits and feasible(cons):
            print(f"\n❌ COUNTEREXAMPLE — an accepting path emits {count} payments "
                  f"(policy allows at most {max_emits}) → multiple payouts from one tx.")
            return 2

    print(f"\n✅ PROVEN — for ALL inputs, no accepting path emits more than {max_emits} "
          f"payment(s). No double-spend / multi-payout.")
    return 0


if __name__ == "__main__":
    mx = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    sys.exit(main(sys.argv[1], mx))
