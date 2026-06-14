"""Prove GUARD-TERMINATION — the invariant unique to a bounded VM.

  for all inputs:  no guard point is crossed more than its maxiter  =>  the hook
                   never dies with GUARD_VIOLATION

On Xahau every loop must carry a `_g(id, maxiter)` guard; crossing it more than
`maxiter` times in one invocation kills the hook at runtime. xahc lint checks a
guard is PRESENT, not that `maxiter` actually bounds the iterations. A loop whose
trip count an attacker can push past its budget passes lint and blows up on-chain.

This driver proves no input can do that — or hands back the input that can. The
engine counts `_g` crossings 1:1 with the host (see prover.py host_call `_g`), so a
fixed-bound loop (e.g. `i < 20` under XAHC_GUARD(20)) trips nothing, while a
data-dependent loop terminates as a violation the moment a feasible path exceeds
its budget. No unroll slack — guard-termination demands exactness.

Usage: python prove_termination.py <hook.wasm>
"""
import sys
import z3
from prover import Engine, feasible


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    print(f"explored: {len(e.accepts)} accepting, {len(e.rollbacks)} rolling back, "
          f"{len(e.guard_viols)} guard-violation path(s)")

    for gid, maxiter, cons in e.guard_viols:
        if not feasible(cons):
            continue
        s = z3.Solver()
        s.add(*cons)
        s.check()
        m = s.model()
        ev = lambda bs: bytes(m.eval(b, model_completion=True).as_long() & 0xFF for b in bs)
        print(f"\n❌ COUNTEREXAMPLE — guard 0x{gid:08X} (budget {maxiter}) can be crossed "
              f"MORE than {maxiter} times → GUARD_VIOLATION (hook killed):")
        # surface whichever inputs drive the over-iteration
        for name in ("amt", "param:CNT", "param:N", "dest", "origin"):
            bs = e.inputs.get(name)
            if bs:
                print(f"   {name} = {ev(bs).hex().upper()}")
        return 2

    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound before its guard "
              "tripped; cannot claim termination.")
        return 3

    print("\n✅ PROVEN — for ALL inputs, no guard is ever crossed past its budget; "
          "the hook can never die with GUARD_VIOLATION.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
