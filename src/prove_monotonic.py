"""Prove STATE-MONOTONICITY — a persisted value never moves backwards.

  for all inputs:  accept  =>  value written to state key K  >=  value read from K

The canonical use is replay protection: a stored nonce / sequence / high-water mark
that must only ever increase. A hook that can be driven to overwrite it with a
SMALLER value is a replay or rollback vulnerability. The engine models `state`
(returns a symbolic prior value — the adversarial case: the slot already holds
something) and `state_set` (records the written value per path); this driver checks
no accepting path writes a value below what it read.

Usage: python prove_monotonic.py <hook.wasm> [--strict] [--field SLOTHEX:OFF:LEN]
  --strict : require STRICTLY increasing (written > old); default is non-decreasing.
  --field  : check only a byte sub-field of one packed slot (e.g. 01:0:8 = the tick field of a
             [tick|resource] slot). Default: every written slot's whole value.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate, vacuity_guard
from field import parse_field, bv_byte_slice


def main(path: str, strict: bool = False, field=None) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    print(f"explored: {len(e.accepts_full)} accepting path(s); "
          f"state keys written: {sorted({k for _, _, w in e.accepts_full for k in w})}"
          + (f"; targeting field {field}" if field else ""))

    # Count comparisons ACTUALLY performed. A PROVEN is only sound if at least one feasible
    # accepting path's write was checked against its prior value — otherwise it is VACUOUS
    # (e.g. --field targets a slot no path writes, or the hook persists no state at all). [audit
    # FS-CRIT-1 / FS-HIGH-1: --field on an unwritten key fell through to a false PROVEN.]
    n_checked = 0
    for code, cons, writes in e.accepts_full:
        # only consider paths that are actually reachable
        if not feasible(cons):
            continue
        # --field restricts the check to ONE sub-field of ONE slot (a packed next_state where
        # different byte-fields have different invariants). Default: every written key, whole value.
        items = writes.items()
        if field is not None:
            if field.key not in writes:
                continue   # this path doesn't persist the targeted slot — nothing to check here
            items = [(field.key, writes[field.key])]
        for kn, wval in items:
            n_checked += 1
            # Fail-closed: a key read at inconsistent widths has an AMBIGUOUS prior model in
            # state_old, so the prior-vs-written comparison may not reflect what this path read.
            if kn in e.state_old_overwritten:
                print(f"\n⚠️ INCONCLUSIVE — state[{kn}] was read at inconsistent byte-widths "
                      f"(ambiguous prior-value model); refusing PROVEN (fail closed).")
                return 3
            old_bytes = e.state_old.get(kn)
            # SOUND: a write to a key that was NEVER read on any path means the
            # hook overwrites persisted state with NO regard for its prior value —
            # i.e. an unconditional `state_set(NONCE, attacker_value)`. That is the
            # canonical replay/rollback bug, NOT a safe case. Treat it as a
            # COUNTEREXAMPLE (state can move backwards because nothing constrains it
            # to the prior value). NEVER silently skip it (the old bug emitted a
            # vacuous PROVEN here).
            if not old_bytes:
                print(f"\n❌ COUNTEREXAMPLE — accept writes state[{kn}] WITHOUT ever "
                      f"reading it (no prior-value comparison constrains the write):")
                print(f"   the stored value is overwritten unconditionally → an "
                      f"attacker-supplied (possibly smaller/replayed) value is "
                      f"accepted. State is NOT monotonic.")
                return 2
            old = z3.Concat(*old_bytes) if len(old_bytes) > 1 else old_bytes[0]
            if old.size() != wval.size():
                # A width mismatch means we CANNOT compare the written value to the
                # prior value, so monotonicity is unproven for this write. Refuse to
                # claim PROVEN — report INCONCLUSIVE rather than silently passing.
                print(f"\n⚠️ INCONCLUSIVE — accept writes state[{kn}] with a byte-width "
                      f"({wval.size() // 8}B) different from what it read "
                      f"({old.size() // 8}B); the written and prior values are not "
                      f"comparable, so monotonicity cannot be proven. Not a PROVEN pass.")
                return 3
            # When --field is set, compare only the targeted byte sub-field of both values.
            cmp_w, cmp_o = wval, old
            if field is not None:
                try:
                    cmp_w = bv_byte_slice(wval, field.off, field.length)
                    cmp_o = bv_byte_slice(old, field.off, field.length)
                except ValueError as ex:
                    print(f"\n⚠️ INCONCLUSIVE — {ex}; cannot check the field. Not PROVEN.")
                    return 3
            # violation = an accepting path that lands the stored value LOWER
            bad = z3.ULE(cmp_w, cmp_o) if strict else z3.ULT(cmp_w, cmp_o)
            s = z3.Solver(); s.add(*cons); s.add(bad)
            r = s.check()
            if r == z3.sat:
                m = s.model()
                ev = lambda b: m.eval(b, model_completion=True).as_long()
                rel = "<=" if strict else "<"
                tgt = f"[{kn!r} field {field.off}:{field.off + field.length}]" if field else f"state[{kn}]"
                print(f"\n❌ COUNTEREXAMPLE — accept writes {tgt} {rel} its prior value "
                      f"(state moves backwards → replay/rollback):")
                print(f"   written = {ev(cmp_w)}   prior = {ev(cmp_o)}")
                return 2
            if r == z3.unknown:
                # SOUND: Z3 could not decide (timeout/incompleteness). `unknown` is
                # NOT "no counterexample" — refuse to claim PROVEN.
                print(f"\n⚠️ INCONCLUSIVE — the solver returned `unknown` checking "
                      f"monotonicity of state[{kn}] (timeout/incompleteness). "
                      f"Cannot claim PROVEN.")
                return 3

    code = unsound_gate(e)
    if code is not None:
        return code

    # FAIL CLOSED on vacuity: if NO feasible accepting path's write was checked, a PROVEN would be
    # vacuous — the property was never exercised (the headline --field feature makes this trivially
    # reachable via a key/offset that no path writes). Return N/A, never PROVEN. [audit FS-CRIT-1]
    what = (f"monotonicity of field {field.key!r}[{field.off}:{field.off + field.length}] "
            f"(no accepting path writes that slot)") if field is not None \
        else "state monotonicity (no accepting path writes any state)"
    code = vacuity_guard(n_checked, what)
    if code is not None:
        return code

    print(f"\n✅ PROVEN — for ALL inputs, every accepted write to "
          f"{'the targeted field' if field is not None else 'hook state'} is "
          f"{'strictly greater than' if strict else 'never below'} its prior value. "
          f"State is monotonic; no replay/rollback.")
    return 0


if __name__ == "__main__":
    argv = sys.argv[2:]
    fld = None
    if "--field" in argv:
        fld = parse_field(argv[argv.index("--field") + 1])
    sys.exit(main(sys.argv[1], "--strict" in argv, fld))
