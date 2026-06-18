"""Prove SC06 UNCHECKED-RETURN — accept ⟹ every failable state-mutating host call succeeded.

  for all inputs:  accept  =>  every state_set / emit performed on this path returned >= 0
                               (a failure was checked and rolled back, never ignored)

THREAT (OWASP SC06): a hook calls a host fn that CAN FAIL — state_set (internal/reserve
error), emit (-13 over-reserve, -1 malformed) — but ignores the return code and ACCEPTs as
if it succeeded. The on-chain effect the hook intended (persist a counter, emit a payment)
silently did NOT happen, yet the transaction is approved. For a spending/authority hook this
is a real exploit: e.g. the budget increment fails, the hook accepts, and the cap is never
written -> unbounded spend.

HOW THIS IS MODELED (opt-in, sound):
  Engine.check_mutation_ret = True makes state_set / emit return a SYMBOLIC 64-bit code that
  MAY be negative (the failure the host can return) instead of a concrete success. A hook that
  CHECKS the code (XAHC_TRY -> rollback on < 0) thereby constrains it >= 0 on every accept
  path; a hook that IGNORES it leaves the code free. So:
    accept ∧ (some mutation return < 0) feasible  ->  the failure was UNCHECKED  -> CEX
    accept forces every mutation return >= 0       ->  all checked               -> PROVEN

This default-off flag leaves every other driver's concrete-success model unchanged.

SCOPE / fail-closed: covers the host fns the engine models as failable state mutations
(state_set, emit). An accepting path that performs NO such call has nothing to check ->
reported N/A (exit 1), never a silent PROVEN. solver `unknown` / unsupported opcode / hit
unroll bound / float over-approx => INCONCLUSIVE, never PROVEN. A hook that can never accept
makes the property vacuous; that is disclosed (0 accepting paths) rather than claimed.

Usage: python prove_unchecked_return.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = N/A.
"""
import sys
import z3
from prover import Engine, feasible


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.check_mutation_ret = True
    e.run()

    accepts = e.mutation_rets_on_accept
    feasible_accepts = [(c, r) for (c, r) in accepts if feasible(c)]

    # FAIL CLOSED FIRST (CLAUDE.md): if the analysis was INCOMPLETE — a symbolic-float
    # over-approx, an unsupported opcode, or an unroll-bound truncation — it may have ERASED the
    # accept paths / mutations before they were snapshotted. Reporting N/A ("property doesn't
    # apply") for an incomplete run mislabels incompleteness as inapplicability. So gate before
    # the N/A early-returns: incompleteness => INCONCLUSIVE(3), never N/A(1).
    if e.float_overapprox or e.unsupported or e.hit_bound or getattr(e, "analysis_errors", None):
        why = []
        if e.float_overapprox: why.append(f"float op(s) {sorted(e.float_overapprox)} over-approximated")
        if e.unsupported: why.append(f"unsupported opcode(s) {sorted(e.unsupported)} reached")
        if e.hit_bound: why.append("a loop exceeded the unroll bound")
        if getattr(e, "analysis_errors", None):
            why.append(f"path step error(s) {sorted(e.analysis_errors)} (dropped path)")
        print(f"\n⚠️ INCONCLUSIVE — analysis incomplete ({'; '.join(why)}); accept paths/mutations "
              "may be unexplored, so cannot claim N/A or PROVEN.")
        return 3

    if not feasible_accepts:
        print("N/A — the hook has no feasible accepting path; the universal "
              "accept ⟹ checked-return property is vacuous (0 accepting paths). Not claimed.")
        return 1

    total_muts = sum(len(rets) for _c, rets in feasible_accepts)
    if total_muts == 0:
        print("N/A — no accepting path performs a failable state-mutating host call "
              "(state_set / emit); there is no return code to check. (Read-only / "
              "pass-through accept paths only.)")
        return 1

    print(f"explored: {len(feasible_accepts)} accepting path(s); "
          f"{total_muts} state_set/emit return(s) to check")

    for cons, rets in feasible_accepts:
        for ret, label in rets:
            # Is it feasible to ACCEPT while this mutation's return is NEGATIVE (failed)?
            s = z3.Solver()
            s.set("timeout", 120000)
            s.add(*cons)
            s.add(ret < z3.BitVecVal(0, 64))   # z3py `<` on a BitVec is SIGNED: < 0 = failure code
            r = s.check()
            if r == z3.unknown:
                print(f"\n⚠️ INCONCLUSIVE — solver `unknown` while checking {label}; not PROVEN.")
                return 3
            if r == z3.sat:
                print(f"\n❌ COUNTEREXAMPLE — an accepting path IGNORES a failed {label}:")
                print(f"   the host can return {label} < 0 (failure), yet the hook still "
                      "ACCEPTs — the intended state mutation / emission silently did not happen.")
                print("   Fix: check the return (e.g. XAHC_TRY) and roll back on < 0.")
                return 2

    # (fail-closed incompleteness gates already checked at the top, before the N/A returns.)
    print("\n✅ PROVEN — for ALL inputs, every accepting path checked the return code of each "
          "failable state_set / emit it performed (no accept proceeds past a host-call "
          "failure). SC06 unchecked-return: clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
