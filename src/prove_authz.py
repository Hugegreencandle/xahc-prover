"""Prove AUTHORIZATION (access control) — OWASP SC01, the #1 real-world loss class.

  for all inputs:  accept  =>  originating account == hook_account (owner)

Scope note: this strict form treats EVERY accept as owner-only (right for a withdrawal /
admin gate hook). For a hook that legitimately accepts non-owner txns on some paths, scope
the check to the privileged accept code (filter `code ==` the payout/admin accept).

Engine inputs used: "origin" (sfAccount, 20 bytes) and "hookacc" (hook_account, 20 bytes).
Fail-closed: solver `unknown` / unsupported opcode / hit unroll bound => INCONCLUSIVE.

Usage: python prove_authz.py <hook.wasm>
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    origin = e.inputs.get("origin")
    me = e.inputs.get("hookacc")
    if not origin or not me:
        print("ERROR: hook does not read BOTH sfAccount (otxn account) and hook_account — "
              "authorization invariant N/A.")
        return 1

    not_owner = z3.Or(*[origin[i] != me[i] for i in range(20)])
    print(f"explored: {len(e.accepts)} accepting path(s)")

    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        s.add(not_owner)                         # an accept by someone who isn't the owner
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned `unknown` on an accept path; cannot claim PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long() & 0xFF
            ov = bytes(ev(b) for b in origin)
            mv = bytes(ev(b) for b in me)
            print("\n❌ COUNTEREXAMPLE — the hook ACCEPTS a transaction from a non-owner account:")
            print(f"   originating account = {ov.hex().upper()}")
            print(f"   hook owner          = {mv.hex().upper()}")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the hook only accepts transactions whose originating "
          "account is the owner. No unauthorized trigger.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
