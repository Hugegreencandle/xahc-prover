"""Prove CONSTANT-PRODUCT (no-drain) safety for an AMM/pool swap Hook.

  for all inputs:  accept  =>  newRX · newRY  >=  oldRX · oldRY

The pool's constant product k = RX·RY must never DECREASE on an accepted swap — if it can, the pool
was drained / LP-backed value extracted. The iconic AMM safety property ("can't be drained"). RX, RY
are two 64-bit reserve slots in hook state (default keys "RX"/"RY"; override via args).

Engine: reserves come from state — oldRX/oldRY are the PRIOR values read (e.state_old), newRX/newRY
are the values WRITTEN on the accept path (e.accepts_full writes). Products are widened to 160-bit
(ZeroExt) BEFORE multiplying so a 128-bit product can NEVER spuriously wrap (the load-bearing
modeling fact — a wrap would be a false counterexample; here it can't happen).

Fail-closed (a false PROVEN on an AMM = drained funds): solver `unknown` -> INCONCLUSIVE; a reserve
written WITHOUT its prior being read -> the new product is unconstrained vs the prior -> COUNTEREXAMPLE
(the hook updates reserves with no regard for k). N/A if no accept writes BOTH reserve slots.

Usage: python prove_constant_product.py <hook.wasm> [RX_key] [RY_key]
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate
from smt_export import emit_query

W = 160  # widen reserves to 160 bits before multiplying (64*64 = 128-bit product, fits with margin)


def _val(bytes_or_bv):
    return z3.Concat(*bytes_or_bv) if isinstance(bytes_or_bv, list) and len(bytes_or_bv) > 1 else (
        bytes_or_bv[0] if isinstance(bytes_or_bv, list) else bytes_or_bv)


def _w160(bv):
    return z3.ZeroExt(W - bv.size(), bv) if bv.size() < W else bv


def main(path: str, rx_key: str = "RX", ry_key: str = "RY") -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    written = sorted({k for _, _, w in e.accepts_full for k in w})
    print(f"explored: {len(e.accepts_full)} accepting path(s); reserves=({rx_key!r},{ry_key!r}); "
          f"state keys written: {written}")

    # Fail-closed: if a reserve slot's prior-value model was overwritten by an inconsistent-width
    # read, a path's actual oldRX/oldRY may differ from e.state_old → we can't soundly pair old/new.
    if rx_key in e.state_old_overwritten or ry_key in e.state_old_overwritten:
        print("\n⚠️ INCONCLUSIVE — a reserve slot was read with inconsistent byte-widths (the "
              "prior-value model is ambiguous); refusing PROVEN (fail closed).")
        return 3

    n_checked = 0
    for code, cons, writes in e.accepts_full:
        if not feasible(cons):
            continue
        if rx_key not in writes or ry_key not in writes:
            # this accept doesn't update BOTH reserves -> not a swap path; skip (N/A unless some
            # path DOES update both). A path writing only ONE reserve can't be reasoned about for k.
            continue
        n_checked += 1
        newRX, newRY = writes[rx_key], writes[ry_key]

        # oldRX/oldRY: the PRIOR reserve values (read-before-write). If a reserve was written WITHOUT
        # its prior being read, nothing ties the new product to the old -> k is unconstrained ->
        # drainable. Fail-closed: a fresh free symbolic old makes (k_new < k_old) satisfiable -> CEX.
        ox = e.state_old.get(rx_key)
        oy = e.state_old.get(ry_key)
        if not ox or not oy:
            print(f"\n❌ COUNTEREXAMPLE — accept writes a reserve WITHOUT reading its prior value: "
                  f"the swap updates reserves with no regard for the old product, so k can drop "
                  f"(pool drainable). (read both {rx_key}/{ry_key} before writing to enforce k.)")
            return 2
        oldRX, oldRY = _val(ox), _val(oy)
        if oldRX.size() != newRX.size() or oldRY.size() != newRY.size():
            print("\n⚠️ INCONCLUSIVE — reserve read/write byte-widths differ; can't compare k "
                  "(fail closed).")
            return 3

        k_old = _w160(oldRX) * _w160(oldRY)
        k_new = _w160(newRX) * _w160(newRY)
        s = z3.SolverFor("QF_BV")             # bit-vector-specialized (bit-blasts the nonlinear product)
        s.set("timeout", 20000)               # nonlinear BV is incomplete; fail-closed (unknown -> INCONCLUSIVE)
        s.add(*cons)
        s.add(z3.ULT(k_new, k_old))           # an accept where the product DROPS = a drain
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned unknown on the k-monotonicity query (fail closed).")
            return 3
        if r == z3.sat:
            print(f"\n❌ COUNTEREXAMPLE — an accepting path (code {code}) makes "
                  f"newRX·newRY < oldRX·oldRY: the constant product drops, the pool can be drained.")
            return 2
        emit_query(s, "constant-product")     # unsat here: this swap path preserves k

    if n_checked == 0:
        print(f"\n— N/A — no accepting path writes BOTH reserve slots ({rx_key!r},{ry_key!r}); "
              "not an AMM-swap hook (or wrong reserve keys).")
        return 1

    code = unsound_gate(e)
    if code is not None:
        return code

    print(f"\n✅ PROVEN — for ALL inputs, accept ⟹ newRX·newRY ≥ oldRX·oldRY. The constant product "
          "never decreases; the pool cannot be drained by a swap.")
    return 0


if __name__ == "__main__":
    rk = sys.argv[2] if len(sys.argv) > 2 else "RX"
    ryk = sys.argv[3] if len(sys.argv) > 3 else "RY"
    sys.exit(main(sys.argv[1], rk, ryk))
