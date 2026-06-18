"""Shared FAIL-CLOSED soundness harness for every invariant driver.

SOUNDNESS IS THE PRODUCT (see CLAUDE.md): a false PROVEN is catastrophic. Two failure classes the
audits kept finding, ONE per-driver block at a time:

  1. OVER-APPROXIMATION leak — the engine replaced a value it couldn't model soundly (symbolic
     float, unsupported opcode, hit unroll bound) with a fresh over-approximating symbol; a PROVEN
     that depends on such a value is unsound. Every driver hand-rolled this gate, and a driver that
     forgot one branch could emit a false PROVEN.
  2. VACUOUS PROVEN — a driver iterates its accepting paths and, finding ZERO feasible ones,
     falls through to its PROVEN print. "True for all zero cases" is not a safety proof.

Centralizing both means a driver gets the full gate by calling ONE function, and the gate can't be
partially forgotten. Both helpers fail toward NOT-PROVEN (INCONCLUSIVE / N/A) — the safe direction.
"""
from __future__ import annotations


def unsound_gate(e) -> int | None:
    """Return 3 (INCONCLUSIVE) with a printed reason if the engine over-approximated ANYTHING that
    could taint a PROVEN — symbolic-float over-approximation, an unsupported opcode, or a hit
    unroll bound. Else None. Call this immediately BEFORE emitting PROVEN. Checking all three is a
    superset of any single driver's old tail (strictly more fail-closed = safe)."""
    if getattr(e, "float_overapprox", None):
        print(f"\n⚠️ INCONCLUSIVE — float op(s) {sorted(e.float_overapprox)} over-approximated "
              "(no sound equality to the true XFL result); cannot claim PROVEN.")
        return 3
    if getattr(e, "unsupported", None):
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} "
              "(e.g. br_table / call_indirect) reached during analysis; cannot claim PROVEN.")
        return 3
    if getattr(e, "hit_bound", False):
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the guard unroll bound; the unexplored tail "
              "could violate the property. Cannot claim PROVEN.")
        return 3
    if getattr(e, "analysis_errors", None):
        print(f"\n⚠️ INCONCLUSIVE — the engine could not soundly step some path(s) "
              f"{sorted(e.analysis_errors)} (e.g. a symbolic value where a concrete was required); "
              "that path was dropped. Cannot claim PROVEN.")
        return 3
    return None


def vacuity_guard(n_feasible_accepts: int, what: str) -> int | None:
    """Return 1 (N/A) — NEVER PROVEN — when zero feasible accepting paths exercised the property.
    A PROVEN over an empty accept set is VACUOUS. `what` describes the property for the message."""
    if n_feasible_accepts <= 0:
        print(f"N/A — no feasible accepting path exercises {what}; the property was not "
              "exercised on any reachable accept. Not claimed (a PROVEN here would be vacuous).")
        return 1
    return None
