"""Prove QUORUM-GATE (N-of-M multisig): funds release ONLY after at least THR distinct signers approve.

The invariant behind a multisig treasury / N-of-M escrow: each authorized signer's approval sets a bit in
an approval mask (state slot 0x01); the release fires only once the number of set bits reaches the
threshold THR. We prove, for ALL inputs:

    accept-with-emit  =>  popcount(approval_mask persisted on this path)  >=  THR     (param "THR", 8B BE)

The driver computes the TRUE popcount independently of the hook — so a hook that MIScounts (releases on
fewer real approvals) is caught as a COUNTEREXAMPLE. The bitmask makes approvals inherently DISTINCT (one
signer approving twice sets the same bit), and the companion per-bit authorization (only signer i sets
bit i) is a separate property (prove_authz-style) the hook must also satisfy — noted in SCOPE.

Fail-closed (a false PROVEN certifies a treasury that releases below quorum — unauthorized spend):
  • THR absent -> N/A (not a quorum hook).
  • An emit path that persists NO approval mask (slot 0x01), or where popcount can be < THR, -> CEX.
  • N/A if no accepting path emits. solver unknown -> INCONCLUSIVE; unsound_gate before any PROVEN.

Usage: python prove_quorum.py <hook.wasm>
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate

MASK_KEY = "\x01"   # state slot holding the approval bitmask


def popcount(bv):
    w = bv.size()
    return z3.Sum([z3.ZeroExt(w - 1, z3.Extract(i, i, bv)) for i in range(w)])   # w-bit count


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    thr_b = e.inputs.get("param:THR")
    if not thr_b:
        print("— N/A — hook reads no THR (quorum threshold) param; the quorum property is not exercised. "
              "Not claimed.")
        return 1
    THR = z3.Concat(*thr_b) if len(thr_b) > 1 else thr_b[0]
    # SGM = the designated signer-bit mask. SOUNDNESS: the engine treats the PRIOR mask (slot 0x01) as
    # symbolic, so it may carry junk high bits a real run never sets. Counting ALL bits would let a hook
    # emit on junk -> false PROVEN. We count ONLY the designated bits (mask & SGM), so junk outside SGM
    # can never satisfy quorum. Required — without it the count isn't soundly bounded.
    sgm_b = e.inputs.get("param:SGM")
    if not sgm_b:
        print("— N/A — hook reads no SGM (signer-bit mask) param; the designated approval bits are "
              "undefined, so quorum can't be soundly counted. Not claimed.")
        return 1
    SGM = z3.Concat(*sgm_b) if len(sgm_b) > 1 else sgm_b[0]

    n = len(e.accepts_full)
    if len(e.emits_on_accept) != n:
        print("\n⚠️ INCONCLUSIVE — accept/emit path lists are not aligned; refusing PROVEN.")
        return 3

    n_emit_paths = 0
    for i in range(n):
        code, cons, writes = e.accepts_full[i]
        _, _emits, emit_count = e.emits_on_accept[i]
        if not feasible(cons):
            continue
        if emit_count == 0:
            continue
        n_emit_paths += 1
        if MASK_KEY not in writes:
            print(f"\n❌ COUNTEREXAMPLE [quorum] — accept code {code} EMITS but persists no approval mask "
                  f"(slot 0x{ord(MASK_KEY):02x}): the release does not depend on a recorded quorum.")
            return 2
        mask = writes[MASK_KEY]
        sgm = SGM if SGM.size() == mask.size() else (
            z3.ZeroExt(mask.size() - SGM.size(), SGM) if SGM.size() < mask.size()
            else z3.Extract(mask.size() - 1, 0, SGM))
        pc = popcount(mask & sgm)                 # TRUE approvals over the DESIGNATED bits only (sound)
        thr = THR if THR.size() == pc.size() else (
            z3.ZeroExt(pc.size() - THR.size(), THR) if THR.size() < pc.size()
            else z3.Extract(pc.size() - 1, 0, THR))
        s = z3.Solver(); s.set("timeout", 20000)
        s.add(*cons)
        s.add(z3.ULT(pc, thr))                    # ...emits while fewer than THR signers have approved
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [quorum] — solver `unknown` on an accept path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE [quorum] — an accepting path releases below quorum (accept code "
                  f"{code}): approvals = {ev(pc)} < THR = {ev(thr)}.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    if n_emit_paths == 0:
        print("— N/A — no accepting path emits a payment; the quorum property is not exercised.")
        return 1

    print("\n✅ PROVEN [quorum] — for ALL inputs, every emitting accept path persists an approval mask with "
          "popcount >= THR. The treasury releases ONLY once at least THR distinct signers have approved.")
    print("   SCOPE: the bitmask makes approvals distinct; per-bit authorization (only signer i sets bit i) "
          "is a companion property the hook enforces separately. Pairs with emit-dst-lock + a released-flag.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
