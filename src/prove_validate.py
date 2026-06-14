"""Prove INPUT VALIDATION / fail-closed default — OWASP SC05.

  for all inputs:  accept  =>  the required hook parameter KEY was PRESENT
                                (host return >= 0, not an absent/negative sentinel)

Catches the classic footgun: the hook reads hook_param(KEY), ignores the negative
"absent" return, and treats the buffer as 0 — so an unset param becomes "limit 0 = allow",
"flag absent = pass". The engine models the host return for KEY as the symbolic 64-bit
`hook_param_ret:KEY`; a correct hook constrains it (== expected length) before accepting.

Fail-closed: solver `unknown` / unsupported / hit bound => INCONCLUSIVE.

Usage: python prove_validate.py <hook.wasm> [KEY]   (KEY default "LIM")
"""
import sys
import z3
from prover import Engine


def main(path: str, key: str = "LIM") -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    ret = e.inputs.get(f"hook_param_ret:{key}")
    if ret is None:
        print(f"ERROR: hook never reads hook_param({key}) — nothing to validate. "
              f"(Pass the actual required key as argv[2].)")
        return 1

    print(f"explored: {len(e.accepts)} accepting path(s); checking param '{key}' presence")

    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        s.add(ret < 0)                           # signed: a negative host return = param ABSENT
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            print(f"\n❌ COUNTEREXAMPLE — the hook ACCEPTS even when required param '{key}' is ABSENT:")
            print(f"   hook_param({key}) returned a negative (not-present) code, yet the hook "
                  f"proceeded — the unset/garbage value was trusted (fail-OPEN).")
            return 2

    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} reached; not PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; not PROVEN.")
        return 3

    print(f"\n✅ PROVEN — for ALL inputs, the hook never accepts unless required param '{key}' "
          f"is present. Fail-closed.")
    return 0


if __name__ == "__main__":
    k = sys.argv[2] if len(sys.argv) > 2 else "LIM"
    sys.exit(main(sys.argv[1], k))
