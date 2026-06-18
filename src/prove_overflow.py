"""Prove a uint64 OVERFLOW can't BYPASS THE LIMIT CHECK (drops+tip vs LIM) — OWASP SC07/09.

SCOPE: proves the specific property below — an accepting path's TRUE (un-wrapped) total never
exceeds LIM. This is NOT a proof that the hook is free of ALL arithmetic overflow; an unrelated
wrap elsewhere (e.g. a product not feeding the limit check) is out of scope. Semi-specialized to
this shape (like prove_limit) — do not read it as "no overflow anywhere".

Demo shape (semi-specialized, like prove_limit): a hook accepts when
(incoming_drops + TIP) <= LIM. If `drops + tip` wraps uint64, the hook's 64-bit check
passes for an effectively over-limit total. This spec recomputes the sum WIDE (128-bit)
and flags any accepting path where the TRUE total exceeds LIM — which can only happen via
a wrap the hook failed to guard.

Engine inputs: "amt" (sfAmount), "param:TIP", "param:LIM".
Fail-closed: solver unknown / unsupported / hit bound => INCONCLUSIVE.

Usage: python prove_overflow.py <hook.wasm>
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate

W = 128


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    amt = e.inputs.get("amt")
    tip = e.inputs.get("param:TIP")
    lim = e.inputs.get("param:LIM")
    if not (amt and tip and lim):
        print("ERROR: expected a hook reading sfAmount + params TIP and LIM.")
        return 1

    drops = z3.ZeroExt(W - 64, z3.Concat(amt[0] & 0x3F, *amt[1:]))
    tipv = z3.ZeroExt(W - 64, z3.Concat(*tip[:8]))
    limv = z3.ZeroExt(W - 64, z3.Concat(*lim[:8]))
    true_total = drops + tipv                      # cannot wrap at 128-bit

    print(f"explored: {len(e.accepts)} accepting path(s)")
    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        s.add(z3.UGT(true_total, limv))            # truly over the limit, yet accepted
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE — overflow lets an over-limit total be accepted:")
            print(f"   true (drops+tip) = {ev(true_total)}  >  LIM = {ev(limv)}  "
                  f"(the 64-bit sum wrapped below LIM)")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, no accepted total exceeds LIM; the drops+tip sum "
          "cannot wrap past the limit check.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
