"""Prove COMMITMENT-INTEGRITY — an accepted commitment root is the honest hash of the state it
commits to, not a constant / stale / forged value.

  for all inputs:  accept  =>  committed_root (slot 0x02)  ==  SHA512Half(state slot 0x01)

This is the property behind on-chain "commitments": a kernel that emits state_root / receipt_root /
world_hash must prove the root is BOUND to the current state — so a verifier (or a fraud proof) can
trust the root identifies exactly that state. The engine models `util_sha512h` as an uninterpreted
function H (same input expression -> same digest; H(x)==H(y) only when x==y), so we prove the
binding WITHOUT modeling SHA internals: a constant root, a hash of STALE state, or a forged value
cannot equal H(the state actually persisted) for all inputs -> COUNTEREXAMPLE.

  STATE_KEY  0x01  the state being committed (the canonical value: the staged write if the path
                   persists it, else the prior value it read)
  COMMIT_KEY 0x02  the committed root (must be a 32-byte SHA-512Half)

N/A (1) if no accepting path persists the commit slot. INCONCLUSIVE (3) on any over-approximation.

Usage: python prove_commitment.py <hook.wasm> [--state-key HEX] [--commit-key HEX]
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate

STATE_KEY = "\x01"
COMMIT_KEY = "\x02"


def main(path: str, state_key: str = STATE_KEY, commit_key: str = COMMIT_KEY) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    commit_writes = [(c, cons, w) for (c, cons, w) in e.accepts_full if commit_key in w]
    if not commit_writes:
        print(f"N/A — no accepting path persists the commit slot (key 0x{ord(commit_key):02x}); "
              "the commitment-integrity property was not exercised. Not claimed.")
        return 1

    print(f"explored: {len(e.accepts_full)} accepting path(s) "
          f"({len(commit_writes)} persist the commit slot 0x{ord(commit_key):02x}); "
          f"state slot 0x{ord(state_key):02x}")

    for code, cons, writes in commit_writes:
        if not feasible(cons):
            continue
        root = writes[commit_key]
        if root.size() != 256:
            print(f"\n⚠️ INCONCLUSIVE — the committed value is {root.size() // 8}B, not a 32-byte "
                  "SHA-512Half; cannot check commitment integrity. Not PROVEN.")
            return 3

        # The CANONICAL state this root must commit to: the value the hook persists to the state
        # slot on this path, else (read-only commit) the prior value it read. If neither exists,
        # the commitment is bound to NOTHING -> a forgeable root (CEX).
        if state_key in writes:
            canon = writes[state_key]
        else:
            old = e.state_old.get(state_key)
            if not old:
                print(f"\n❌ COUNTEREXAMPLE — accept persists a commit root WITHOUT reading or "
                      f"writing the state slot 0x{ord(state_key):02x}: the root is bound to no "
                      "state (forgeable / unverifiable commitment).")
                return 2
            canon = z3.Concat(*old) if len(old) > 1 else old[0]

        # NEGATION of the invariant: an accepting path where committed_root != H(canonical state).
        s = z3.Solver(); s.set("timeout", 120000)
        s.add(*cons)
        s.add(root != e.sha512h(canon))
        r = s.check()
        if r == z3.unknown:
            print(f"\n⚠️ INCONCLUSIVE — solver `unknown` on accept code {code}; not PROVEN.")
            return 3
        if r == z3.sat:
            print("\n❌ COUNTEREXAMPLE — accept persists a commit root that is NOT the hash of the "
                  "committed state (constant / stale / forged root):")
            print("   committed_root != SHA512Half(persisted state) — the root does not identify "
                  "the state it claims to commit.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, every accepted commit root equals SHA512Half of the state "
          "it commits (committed_root == H(state)). The root is cryptographically BOUND to its "
          "state: no constant, stale, or forged root is accepted. (SCOPE: single state slot + "
          "single commit slot per invocation; H modeled as an uninterpreted hash — collision "
          "resistance of SHA-512 is assumed, not proven.)")
    return 0


if __name__ == "__main__":
    argv = sys.argv[2:]
    sk = bytes.fromhex(argv[argv.index("--state-key") + 1]).decode("latin1") if "--state-key" in argv else STATE_KEY
    ck = bytes.fromhex(argv[argv.index("--commit-key") + 1]).decode("latin1") if "--commit-key" in argv else COMMIT_KEY
    sys.exit(main(sys.argv[1], sk, ck))
