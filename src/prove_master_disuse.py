"""Prove MASTER-KEY DISUSE — quantum key-rotation enforcement (HNDL hardening).

  for all inputs:  (accept AND outgoing)  =>
        otxn_type in {SetRegularKey=5, SignerListSet=12, SetHook=22}   (key/hook mgmt)
        OR  SigningPubKey length != 33                                 (multi-signed)
        OR  SigningPubKey != MPK                                       (regular-key signed)

i.e. no ordinary OUTGOING transaction is signed by the account's unrotatable MASTER key.
This is the property qkey_guard enforces: route routine activity through a rotatable
regular key / signer list so the one key that can never be rotated (the master key, which
hashes to the AccountID) is never exposed on a routine tx — the near-term defense against
Harvest-Now-Decrypt-Later. An on-ledger guarantee XRPL accounts cannot make.

Scope: OUTGOING only (origin == hook_account). A hook legitimately accepts INCOMING txns
(it doesn't police them), so the counterexample is constrained to origin == owner — an
incoming accept is out of scope, not a violation. The master key is identified by direct
byte-compare against the owner-supplied "MPK" hook parameter, because no host fn derives an
AccountID from a public key on-chain (RIPEMD160 is not exposed).

Engine inputs used: origin (sfAccount), hookacc (hook_account), otxn_type,
SigningPubKey bytes + length (otxn_field 0x70003), and param MPK (hook_param).
Fail-closed: solver `unknown` / unsupported opcode / hit unroll bound => INCONCLUSIVE.

Audit scope (rides on any cert — see hooks/qkey_guard.c):
  - Certifies the property only over the BYTE-WIDTH the hook actually compares
    (is_master uses min(len(spk),len(mpk))). For full strength the hook must read
    a 33-byte MPK and compare all 33 bytes (qkey_guard.c does). A shorter compare
    over-rejects (still safe — fails toward COUNTEREXAMPLE, never false-PROVEN).
  - Master-key DISUSE, not compromise defense: management types {5,12,22} are an
    intentional, master-signable escape hatch (brick-safety), out of scope here.
  - Assumes the hook fires (HookOn) and that MPK is genuinely the master pubkey.

Usage: python prove_master_disuse.py <hook.wasm>
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate
from smt_export import emit_query

SF_SIGNING_PUB_KEY = 0x70003  # sfSigningPubKey: STI_BLOB (7), nth 3
MGMT_TYPES = (5, 12, 22)      # SetRegularKey, SignerListSet, SetHook


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    origin = e.inputs.get("origin")
    me = e.inputs.get("hookacc")
    tt = e.inputs.get("otxn_type")
    spk = e.inputs.get(f"otxn_field:{SF_SIGNING_PUB_KEY:x}")
    spk_len = e.inputs.get(f"otxn_field_ret:{SF_SIGNING_PUB_KEY:x}")
    mpk = e.inputs.get("param:MPK")

    if not origin or not me:
        print("ERROR: hook does not read BOTH sfAccount and hook_account — cannot scope to "
              "outgoing txns; master-disuse invariant N/A.")
        return 1
    if tt is None or spk is None or spk_len is None or mpk is None:
        print("ERROR: hook does not read otxn_type, sfSigningPubKey, AND the MPK hook param — "
              "master-disuse invariant N/A (this hook does not police the signing key).")
        return 1

    n = min(len(spk), len(mpk))
    outgoing = z3.And(*[origin[i] == me[i] for i in range(20)])
    not_mgmt = z3.And(*[tt != z3.BitVecVal(t, tt.size()) for t in MGMT_TYPES])
    single_signed = (spk_len == z3.BitVecVal(33, spk_len.size()))
    is_master = z3.And(*[spk[i] == mpk[i] for i in range(n)])

    print(f"explored: {len(e.accepts)} accepting path(s)")

    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        # an OUTGOING accept of an ORDINARY tx signed by the MASTER key
        s.add(outgoing, not_mgmt, single_signed, is_master)
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned `unknown` on an accept path; cannot claim PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long() & 0xFF
            print("\n❌ COUNTEREXAMPLE — the hook ACCEPTS an ordinary outgoing tx signed by the master key:")
            print(f"   otxn_type     = {m.eval(tt, model_completion=True).as_long()}")
            print(f"   SigningPubKey = {bytes(ev(b) for b in spk[:n]).hex().upper()}")
            print(f"   MPK (master)  = {bytes(ev(b) for b in mpk[:n]).hex().upper()}")
            return 2
        emit_query(s, "master_disuse")  # unsat: path proven — record the obligation

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the hook never accepts an ordinary outgoing transaction "
          "signed by the master key. Routine activity must use a rotatable regular key or signer "
          "list; the master key is admitted only for key/hook management (brick-safe escape hatch).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
