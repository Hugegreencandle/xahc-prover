"""Prove HASHLOCK (HTLC escrow): funds release ONLY to someone who presents the preimage of a committed hash.

The invariant behind a hash-locked escrow / HTLC / conditional payment: the Hook commits to a hash H, and
releases ONLY when a claimant supplies a preimage P with sha512h(P) == H. We prove, for ALL inputs:

    accept-with-emit  =>  some hashed input's digest == H        (H = committed param "HSH", 32B)

The engine models util_sha512h as an UNINTERPRETED function (H(x)==H(y) only when x==y), so we prove the
binding WITHOUT modeling SHA internals — UNDER the standard collision-resistance assumption (a claimant
can't FIND a second preimage). Records every sha512h(input)->digest the hook computed (engine hash_obs);
an emit path is safe iff its constraints FORCE one recorded digest to equal H.

Fail-closed (a false PROVEN certifies an escrow anyone can drain without the secret — theft):
  • HSH absent -> N/A (not a hashlock escrow).
  • An emit path that hashes nothing, or where NO recorded digest is provably == H (the release doesn't
    require the preimage), -> COUNTEREXAMPLE.
  • N/A if no accepting path emits. solver unknown -> INCONCLUSIVE; unsound_gate before any PROVEN.

Usage: python prove_hashlock.py <hook.wasm>
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    hsh_b = e.inputs.get("param:HSH")
    if not hsh_b:
        print("— N/A — hook reads no HSH (committed-hash) param; the hashlock property is not exercised. "
              "Not claimed.")
        return 1
    if len(hsh_b) != 32:
        print(f"\n⚠️ INCONCLUSIVE — the HSH commitment is {len(hsh_b)}B, not a 32-byte SHA-512Half; cannot "
              "compare against a digest. Not PROVEN.")
        return 3
    H = z3.Concat(*hsh_b)   # 256-bit committed hash

    n = len(e.accepts_full)
    if len(e.emits_on_accept) != n or len(e.hash_obs_on_accept) != n:
        print("\n⚠️ INCONCLUSIVE — accept/emit/hash path lists are not aligned; refusing PROVEN.")
        return 3

    n_emit_paths = 0
    for i in range(n):
        code, cons, _writes = e.accepts_full[i]
        _, _emits, emit_count = e.emits_on_accept[i]
        _, hash_obs = e.hash_obs_on_accept[i]
        if not feasible(cons):
            continue
        if emit_count == 0:
            continue
        n_emit_paths += 1

        # the path is SAFE iff its constraints FORCE at least one hashed digest to equal H
        # (i.e. there is a recorded digest d with UNSAT(cons ^ d != H)).
        forced = False
        for (_inp, digest) in hash_obs:
            if digest.size() != H.size():
                continue
            s = z3.Solver(); s.set("timeout", 20000)
            s.add(*cons); s.add(digest != H)
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE [hashlock] — solver `unknown` proving a digest is forced to H; "
                      "not PROVEN.")
                return 3
            if r == z3.unsat:        # cons => digest == H : this emit requires the matching preimage
                forced = True
                break
        if not forced:
            why = ("the hook hashes nothing on this path" if not hash_obs
                   else "no hashed digest is forced to equal H")
            print(f"\n❌ COUNTEREXAMPLE [hashlock] — an accepting path EMITS but {why} (accept code {code}): "
                  "the release does not require the committed preimage — anyone can drain it.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    if n_emit_paths == 0:
        print("— N/A — no accepting path emits a payment; the hashlock property is not exercised.")
        return 1

    print("\n✅ PROVEN [hashlock] — for ALL inputs, every emitting accept path requires a presented input "
          "whose sha512h equals the committed H. The escrow releases ONLY to a claimant who knows the "
          "preimage.")
    print("   SCOPE: under the collision-resistance of SHA-512Half (util_sha512h modeled as an injective "
          "uninterpreted function). Proves the emit PATH's constraints force a hashed digest == H (a real "
          "hash gate); a contrived hook that gates on a decoy hash still satisfies this (the emit still "
          "requires SOME preimage of H). Pairs with emit-dst-lock + a spent-flag (claim once) for an HTLC.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
