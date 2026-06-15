"""Prove FOREIGN-STATE AUTHORIZATION — OWASP SC01 / return code -34 NOT_AUTHORIZED.

  for all inputs:  accept  =>  every state_foreign_set on the path was AUTHORIZED
                               (the host returned success, which on Xahau happens iff a
                                matching HookGrant from the target account exists)

Hoare triple:
  { hook reaches a state_foreign_set(.., A) call }
  state_foreign_set(.., A)
  { the write succeeds  =>  account A published a HookGrant authorizing this hook }
Proof obligation (negated, per accepting path): is it feasible to ACCEPT while a
state_foreign_set on that path was UNauthorized (host return < 0, NOT_AUTHORIZED -34)?

Why this is the sound formalization: the engine does not (and cannot soundly) enumerate
which HookGrants exist on-ledger, so it models each state_foreign_set host return as a
SYMBOLIC value that MAY be the -34 unauthorized sentinel. A hook is authorized for a write
iff it does NOT proceed-to-accept on the unauthorized branch — i.e. a correct hook checks
the return code and rolls back when it's negative (XAHC_TRY / a `rc < 0` guard). A hook that
ignores the return and accepts anyway is exactly the bug: it would write another account's
state without a grant (the host would reject with -34, but the hook's *logic* treated the
write as done — and on a path where it does succeed, it wrote foreign state it never proved
it was entitled to). This driver flags any accept reachable while an on-path foreign-set was
unauthorized.

Fail-closed: if the engine couldn't pin a foreign-set's target account (foreign_unsound),
or solver `unknown` / unsupported opcode / hit unroll bound => INCONCLUSIVE, never PROVEN.

Usage: python prove_foreign_authz.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = N/A.
"""
import sys
import z3
from prover import Engine


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    # Did ANY accepting path perform a foreign-state write at all?
    any_fset = any(len(fsets) > 0 for _, fsets in e.foreign_sets_on_accept)
    if not any_fset:
        print("ERROR: hook never calls state_foreign_set — foreign-state authorization N/A.")
        return 1

    print(f"explored: {len(e.foreign_sets_on_accept)} accepting path(s); "
          f"checking every foreign-state write is authorized")

    # FAIL CLOSED before any PROVEN: a foreign-set whose target account we couldn't model.
    if e.foreign_unsound:
        print(f"\n⚠️ INCONCLUSIVE — foreign-state op(s) {sorted(e.foreign_unsound)} could not "
              f"be modeled soundly (e.g. non-20-byte target account); cannot prove "
              f"authorization. Refusing to claim PROVEN.")
        return 3

    for cons, fsets in e.foreign_sets_on_accept:
        for acct, granted, ret in fsets:
            s = z3.Solver()
            s.add(*cons)
            s.add(z3.Not(granted))            # this foreign-set was UNauthorized (ret < 0) yet we accepted
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE — solver returned `unknown` on an accept path with a "
                      "foreign-state write; cannot claim PROVEN.")
                return 3
            if r == z3.sat:
                m = s.model()
                print("\n❌ COUNTEREXAMPLE — the hook ACCEPTS after writing ANOTHER account's "
                      "state WITHOUT an authorizing HookGrant:")
                if acct is not None:
                    ev = lambda b: m.eval(b, model_completion=True).as_long() & 0xFF
                    av = bytes(ev(b) for b in acct)
                    print(f"   target account (foreign) = {av.hex().upper()}")
                rv = m.eval(ret, model_completion=True).as_long()
                rv = rv - (1 << 64) if rv >= (1 << 63) else rv
                print(f"   state_foreign_set returned {rv} (negative = NOT_AUTHORIZED / no grant), "
                      f"yet the hook proceeded to accept.")
                return 2

    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} reached; not PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; not PROVEN.")
        return 3

    print("\n✅ PROVEN — for ALL inputs, the hook never accepts a foreign-state write unless it "
          "was authorized (the target account granted it via a HookGrant). No unauthorized "
          "foreign-state mutation.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
