"""Generic DSL invariant checker — prove a one-line property without a hand driver.

  python prove_dsl.py <hook.wasm> "accept implies emitted_total <= incoming_drops"

Verdict shape identical to the hand drivers: all accepting paths UNSAT against the
predicate's negation -> PROVEN (0); any SAT -> COUNTEREXAMPLE (2); Z3 unknown or any
engine taint (float over-approx on an XFL term, unsupported opcode, hit unroll bound,
unparseable emit) -> INCONCLUSIVE (3). A malformed/unsupported expression -> hard
reject (1). The DSL path reuses the engine's exact fail-closed gating — it bypasses none.
"""
import sys
import z3
from prover import Engine
import dsl


def main(path: str, predicate: str) -> int:
    try:
        ast = dsl.parse(predicate)
        dsl.validate(ast)                       # static reject (unknown id / XFL arithmetic)
    except dsl.DSLError as ex:
        print(f"❌ DSL ERROR (rejected, not proven): {ex}")
        return 1
    e = Engine(open(path, "rb").read())
    e.run()
    return evaluate(e, ast, predicate)


def evaluate(e, ast, predicate: str = "") -> int:
    """Check a parsed predicate against an already-run engine. Split out from main() so
    tests can drive the engine state (e.g. inject a float over-approx) and exercise the
    exact gating prove_dsl uses."""
    accepts = e.accepts
    full = e.accepts_full
    emits = e.emits_on_accept
    n = len(accepts)
    if not (len(full) == n and len(emits) == n):
        print("⚠️ INCONCLUSIVE — engine per-path records are not aligned; cannot evaluate soundly.")
        return 3

    print(f"explored: {n} accepting path(s); predicate: {predicate}")

    for i in range(n):
        code, cons = accepts[i]
        ctx = {"code": code, "writes": full[i][2], "emits": emits[i][1], "count": emits[i][2]}
        tr = dsl.Translator(e, ctx)
        try:
            pred = tr.b(ast)
        except dsl._Indeterminate as ind:
            print(f"⚠️ INCONCLUSIVE — {ind} on an accepting path; cannot claim PROVEN.")
            return 3
        except dsl.DSLError as ex:
            # a reference that can't be modeled at all -> hard reject (never a pass)
            print(f"❌ DSL ERROR (rejected, not proven): {ex}")
            return 1
        s = z3.Solver()
        s.add(*cons)
        s.add(z3.Not(pred))                      # look for an accepting path that VIOLATES it
        r = s.check()
        if r == z3.unknown:
            print("⚠️ INCONCLUSIVE — solver returned `unknown` on an accepting path; not PROVEN.")
            return 3
        if r == z3.sat:
            print("\n❌ COUNTEREXAMPLE — an accepting path violates the invariant "
                  f"(accept code {code}).")
            return 2

    # post-loop fail-closed gates (mirror the hand drivers; CEX above takes precedence)
    if dsl.uses_xfl(ast) and e.float_overapprox:
        print(f"\n⚠️ INCONCLUSIVE — XFL term in the predicate but float op(s) "
              f"{sorted(e.float_overapprox)} were over-approximated; cannot claim PROVEN.")
        return 3
    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} reached; "
              f"not PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; not PROVEN.")
        return 3

    print("\n✅ PROVEN — for ALL inputs in scope, every accepting path satisfies the invariant.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('usage: python prove_dsl.py <hook.wasm> "<predicate>"')
        sys.exit(1)
    sys.exit(main(sys.argv[1], " ".join(sys.argv[2:])))
