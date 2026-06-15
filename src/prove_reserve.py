"""Prove RESERVE SAFETY — Xahau return code -38 RESERVE_INSUFFICIENT.

  for all inputs:  accept  =>  balance - (Σ emitted drops + Σ emit fees)  >=  reserve
                               where reserve = base + owner_count * increment

Hoare triple:
  { account has standing balance B, owner_count O, reserve params (base, inc) }
  hook emits payments totalling S (+ fees F) and accepts
  { B - (S + F) >= base + O*inc }    (the account is never driven below its reserve)
Proof obligation (negated, per accepting path): is it feasible to ACCEPT while
  balance - (Σ emits + Σ fees)  <  base + owner_count*inc  ?

Engine modeling (symbolic bitvecs, no concrete ledger):
  - The standing balance, owner_count, reserve base and increment are read by the hook as
    hook parameters BAL / OWNC / RSVB / RSVI (8 bytes each, big-endian) and surface as
    symbolic input bytes. A reserve-aware hook reads these and checks headroom before
    emitting; this driver re-derives the same quantities symbolically and checks the
    invariant against EVERY accepting path.
  - Emitted native drops are extracted per path by the engine (xahc payment template).
  - Each emit's base fee is modeled as a SYMBOLIC value constrained >= the host base fee, so
    the proof must hold for every fee >= base (the real fee is in that set) — outflow is
    therefore NEVER under-counted, which would otherwise be a false PROVEN.

SOUNDNESS / fail-closed (gated BEFORE any PROVEN):
  - If an accepting path emits an amount the engine could not parse (None), the outflow
    cannot be bounded -> INCONCLUSIVE (an unparsed emit could be arbitrarily large).
  - reserve = base + owner_count*inc is computed in 128-bit to avoid wrap; the balance check
    is done in 128-bit too. (A wrap in the *hook's own* 64-bit headroom math is exactly the
    kind of bug this catches — we compute the TRUE values wide.)
  - solver `unknown` / unsupported opcode / hit unroll bound / float over-approx => INCONCLUSIVE.

SCOPE NOTE: this proves the account's XAH balance stays at/above its reserve given the
emitted outflow this hook performs. It models the account's own emits + fees as the outflow;
it does not model exotic balance changes outside the hook's emissions.

Usage: python prove_reserve.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = N/A.
"""
import sys
import z3
from prover import Engine

W = 128


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    bal = e.inputs.get("param:BAL")
    ownc = e.inputs.get("param:OWNC")
    rsvb = e.inputs.get("param:RSVB")
    rsvi = e.inputs.get("param:RSVI")
    if not (bal and ownc and rsvb and rsvi):
        print("ERROR: expected a reserve-aware hook reading hook params BAL (balance), "
              "OWNC (owner_count), RSVB (reserve base), RSVI (reserve increment), each 8 bytes.")
        return 1

    # SOUNDNESS-PRESERVING TRACTABILITY: the engine represents each 8-byte param as 8 separate
    # BitVec(8) symbols, and the hook decodes them with its OWN shift/or expression — so the
    # big-endian value appears in `cons` as a shift/or tree, not a single Concat. A nonlinear
    # product (owner_count*inc) plus unsigned comparisons over such trees is pathological for
    # Z3's bit-blaster (times out). We substitute each param's individual BYTE symbols with the
    # corresponding byte slice of a FRESH clean 64-bit variable, EVERYWHERE (path constraints
    # AND the reserve/balance arithmetic). Byte-level substitution is exact — byte i of the
    # clean var IS that byte symbol — so semantics are unchanged; only the term shape Z3 must
    # bit-blast collapses to flat variables. (bal[0] is the most-significant byte, big-endian.)
    BAL = z3.BitVec("RSV_balance", 64)
    OWN = z3.BitVec("RSV_owner_count", 64)
    BASE = z3.BitVec("RSV_base", 64)
    INC = z3.BitVec("RSV_inc", 64)

    def _byte_subs(byts, clean):
        # byts[0] = MSB ... byts[7] = LSB  (big-endian). Byte k from the high end is bits
        # [ (8-k)*8-1 : (7-k)*8 ] of the clean 64-bit var.
        out = []
        for k, b in enumerate(byts[:8]):
            hi = (8 - k) * 8 - 1
            lo = (7 - k) * 8
            out.append((b, z3.Extract(hi, lo, clean)))
        return out

    subs = (_byte_subs(bal, BAL) + _byte_subs(ownc, OWN)
            + _byte_subs(rsvb, BASE) + _byte_subs(rsvi, INC))

    def z(x):
        return z3.ZeroExt(W - 64, x)

    balance = z(BAL)
    owner_count = z(OWN)
    base = z(BASE)
    inc = z(INC)
    reserve = base + owner_count * inc            # 128-bit: cannot wrap for bounded u64 inputs

    print(f"explored: {len(e.fees_on_accept)} accepting path(s); checking reserve headroom")

    # Walk accepting paths; emits and fees are aligned 1:1 by the engine.
    for (cons, emits, count), (_fc, fees, _c2) in zip(e.emits_on_accept, e.fees_on_accept):
        # FAIL CLOSED: an unparsed emit means outflow is unbounded -> cannot prove.
        if any(x is None for x in emits):
            print("\n⚠️ INCONCLUSIVE — an emitted amount could not be parsed (non-template "
                  "payment); outflow is unbounded, cannot prove reserve safety.")
            return 3
        outflow = z3.BitVecVal(0, W)
        for x in emits:
            outflow = outflow + z(z3.substitute(x, *subs))
        for fbv in fees:
            outflow = outflow + z(z3.substitute(fbv, *subs))

        s = z3.Solver()
        s.set("timeout", 120000)   # fail closed (-> unknown -> INCONCLUSIVE) rather than hang
        s.add(*[z3.substitute(c, *subs) for c in cons])
        # NEGATION of the invariant: accept while the post-outflow balance is below reserve.
        # Use 128-bit unsigned: the breach is (balance < outflow + reserve), which holds both
        # when outflow alone exceeds balance and when it merely eats into the reserve.
        s.add(z3.ULT(balance, outflow + reserve))
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE — an accepting path drives the account BELOW its reserve:")
            print(f"   balance      = {ev(balance)} drops")
            print(f"   outflow      = {ev(outflow)} drops (emits + fees, {count} emit(s))")
            print(f"   reserve      = {ev(reserve)} drops (base {ev(base)} + owner_count "
                  f"{ev(owner_count)} * inc {ev(inc)})")
            print(f"   post-balance = {ev(balance) - ev(outflow)} < reserve -> "
                  f"RESERVE_INSUFFICIENT (-38)")
            return 2

    if e.float_overapprox:
        print(f"\n⚠️ INCONCLUSIVE — float op(s) {sorted(e.float_overapprox)} over-approximated; "
              f"not PROVEN.")
        return 3
    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} reached; not PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; not PROVEN.")
        return 3

    print("\n✅ PROVEN — for ALL inputs, no accepting path drives the account below its XAH "
          "reserve (base + owner_count*increment). Reserve-safe.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
