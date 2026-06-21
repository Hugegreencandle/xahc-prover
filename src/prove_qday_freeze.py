"""Prove Q-DAY FREEZE — a post-quantum recovery vault: once armed, funds move ONLY for whoever knows
the committed quantum-safe secret, even if the account's ed25519/secp256k1 key is later Shor-broken.

The Hook commits a hash QH = sha512h(secret) at install. We prove, for ALL inputs:

    accept AND outgoing  =>  some presented input's sha512h == QH        (QH = committed param "QH", 32B)

i.e. no OUTGOING transaction is accepted unless it revealed the preimage of the commitment. A quantum
adversary holding the broken classical key cannot move funds — they don't know the preimage, and finding
one is a hash pre-image search (Grover-only). This is the on-ledger analog of Ripple's PQC Phase-1
"prove key ownership without exposing the key", as a Xahau Hook.

Engine model: util_sha512h is an injective UNINTERPRETED function (H(x)==H(y) only when x==y), so we prove
the binding UNDER SHA-512Half collision-resistance, without modeling SHA internals. `hash_obs` records
every sha512h(input)->digest the hook computed; an accept path is safe iff its constraints FORCE one
recorded digest to equal QH.

Scope: OUTGOING only (origin == hook_account) — incoming txns are not guarded, so an incoming accept is
out of scope, not a violation (mirrors master-disuse / authz).

Fail-closed (a false PROVEN certifies a vault a quantum thief can drain):
  • QH absent / not 32B -> N/A / INCONCLUSIVE.
  • hook doesn't read sfAccount + hook_account (can't scope outgoing) -> N/A.
  • an OUTGOING accept where NO recorded digest is provably == QH (the spend doesn't require the
    preimage) -> COUNTEREXAMPLE.
  • solver unknown -> INCONCLUSIVE; unsound_gate before any PROVEN.

Usage: python prove_qday_freeze.py <hook.wasm>
Exit 0 PROVEN · 1 N/A · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    qh_b = e.inputs.get("param:QH")
    if not qh_b:
        print("— N/A — hook reads no QH (committed-hash) param; the Q-day-freeze property is not exercised.")
        return 1
    if len(qh_b) != 32:
        print(f"\n⚠️ INCONCLUSIVE — the QH commitment is {len(qh_b)}B, not a 32-byte SHA-512Half; cannot compare. Not PROVEN.")
        return 3
    QH = z3.Concat(*qh_b)

    origin = e.inputs.get("origin")
    me = e.inputs.get("hookacc")
    if not origin or not me:
        print("— N/A — hook does not read BOTH sfAccount and hook_account; cannot scope to OUTGOING txns. "
              "Q-day-freeze invariant not claimed.")
        return 1
    outgoing = z3.And(*[origin[i] == me[i] for i in range(20)])

    n = len(e.accepts_full)
    if len(e.hash_obs_on_accept) != n:
        print("\n⚠️ INCONCLUSIVE — accept/hash path lists are not aligned; refusing PROVEN.")
        return 3

    n_outgoing_accepts = 0
    for i in range(n):
        code, cons, _writes = e.accepts_full[i]
        _, hash_obs = e.hash_obs_on_accept[i]
        if not feasible(cons):
            continue
        # In scope only if this accepting path CAN be an outgoing (origin == owner) tx.
        if not feasible(list(cons) + [outgoing]):
            continue
        n_outgoing_accepts += 1

        # SAFE iff some recorded digest is FORCED to QH on this outgoing accept path:
        #   exists d : UNSAT( cons ^ outgoing ^ d != QH )
        forced = False
        for (_inp, digest) in hash_obs:
            if digest.size() != QH.size():
                continue
            s = z3.Solver(); s.set("timeout", 20000)
            s.add(*cons); s.add(outgoing); s.add(digest != QH)
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE [qday-freeze] — solver `unknown` proving a digest is forced to QH; not PROVEN.")
                return 3
            if r == z3.unsat:
                forced = True
                break
        if not forced:
            why = ("the hook hashes nothing on this path" if not hash_obs
                   else "no hashed digest is forced to equal QH")
            print(f"\n❌ COUNTEREXAMPLE [qday-freeze] — an OUTGOING transaction is ACCEPTED but {why} "
                  f"(accept code {code}): the spend does not require the committed quantum-safe preimage — "
                  "a quantum thief who broke the classical key could drain it.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    if n_outgoing_accepts == 0:
        print("— N/A — no OUTGOING accepting path; the Q-day-freeze property is not exercised.")
        return 1

    print("\n✅ PROVEN [qday-freeze] — for ALL inputs, every OUTGOING transaction the hook accepts must "
          "present an input whose sha512h equals the committed QH. Funds move ONLY for the holder of the "
          "quantum-safe preimage; a Shor-broken classical key alone cannot spend.")
    print("   SCOPE: under SHA-512Half collision-resistance (util_sha512h = injective uninterpreted fn). "
          "Proves the spend requires a preimage of the COMMITTED QH; it does NOT verify QH commits to the "
          "operator's genuine quantum-safe secret (a decoy-hash hook would also pass) — committing the right "
          "secret and keeping it offline are operator responsibilities. The 'no management escape hatch' "
          "guarantee also assumes HookOn subscribes this hook to the fund-moving AND key/hook-management tx "
          "types (the prover analyzes the hook body, not the install config). Losing the secret loses access.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
