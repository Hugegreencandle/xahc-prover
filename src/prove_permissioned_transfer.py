"""Prove PERMISSIONED-TRANSFER — a transfer is accepted only to a VERIFIED counterparty.

  for all inputs:  accept  =>  destination (sfDestination)  ==  the authorized allowlist entry (ALW)

CONTEXT. XRPL just shipped a Permissioned DEX (Ripple+Bitso MXNB, verified 2026-06-09): regulated,
verified-counterparties-only settlement. On XRPL that gate is a protocol AMENDMENT (permissioned
domains). On Xahau the same control is a HOOK — and with xahc-prover it's PROVABLE: "compliance
gated by construction AND by proof." This invariant proves the gate: the hook accepts an outgoing
transfer ONLY when the destination is on the authorized allowlist. (Sibling to `authz`, which gates
on the ORIGINATOR == owner; this gates on the COUNTERPARTY == an allowed account.)

MODEL (v1). The authorized counterparty is a 20-byte HookParameter `ALW` (symbolic to the prover —
proven for ALL allowlist values). The hook reads the transaction's destination (sfDestination ->
"dest") and `ALW`, and must accept only when they match byte-for-byte. We prove no accepting path
admits a destination != the allowlist entry. A hook that does a PARTIAL (prefix-only) compare is
caught: the constraint only pins the compared bytes, so a mismatch on the rest is reachable -> CEX.

  v1 SCOPE: a single authorized destination (ALW). A multi-entry allowlist composes by OR-ing
  several ALW params (future); incoming-side (origin must be verified) is the `authz`-shaped dual
  (future). Xahau has no native credential/permissioned-domain primitive (only DepositPreauth /
  trustline RequireAuth) — so this is the Hook-native gate; a first-class primitive is a possible
  amendment (see HQ Permissioned-DEX intel).

STRICT FORM (like prove_authz): this treats EVERY accept as requiring dest==ALW — right for a hook
whose job is gating transfers (it rolls back anything that isn't an authorized transfer). A hook that
legitimately accepts OTHER tx types on pass-through paths (e.g. `accept("not a payment")`) would
COUNTEREXAMPLE on those paths (dest is unconstrained there) — scope it to the gated accept, or gate
non-transfers with a rollback so every accept is an authorized transfer.

Fail closed: solver `unknown` / unsupported / hit bound -> INCONCLUSIVE. A hook that doesn't read
BOTH a destination and the ALW param -> N/A (the property isn't exercised). vacuity_guard: no
accepting path -> N/A, never a vacuous PROVEN.

Usage: python prove_permissioned_transfer.py <hook.wasm>
Exit 0 = PROVEN, 1 = N/A, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate, vacuity_guard

ALW_KEY = "param:ALW"


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    dest = e.inputs.get("dest")
    alw = e.inputs.get(ALW_KEY)
    if not dest or not alw:
        print("N/A — hook does not read BOTH the transaction destination (sfDestination) and the "
              "authorized-counterparty parameter ALW; the permissioned-transfer property is not "
              "exercised. Not claimed.")
        return 1
    n = min(len(dest), len(alw), 20)
    if n < 20:
        print(f"\n⚠️ INCONCLUSIVE — destination ({len(dest)}B) / ALW ({len(alw)}B) is not a full "
              "20-byte account; cannot prove the counterparty match. Not PROVEN.")
        return 3
    not_authorized = z3.Or(*[dest[i] != alw[i] for i in range(20)])

    print(f"explored: {len(e.accepts)} accepting path(s)")
    n_checked = 0
    for code, cons in e.accepts:
        if not feasible(cons):
            continue
        n_checked += 1
        s = z3.Solver(); s.add(*cons); s.add(not_authorized)
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver `unknown` on an accept path; cannot claim PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long() & 0xFF
            dv = bytes(ev(b) for b in dest)
            av = bytes(ev(b) for b in alw)
            print("\n❌ COUNTEREXAMPLE — the hook ACCEPTS a transfer to an UNAUTHORIZED destination "
                  "(not the allowlisted counterparty):")
            print(f"   destination = {dv.hex().upper()}")
            print(f"   allowlist   = {av.hex().upper()}")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    code = vacuity_guard(n_checked, "permissioned transfer (no feasible accepting path)")
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the hook accepts a transfer only when its destination is the "
          "authorized allowlisted counterparty (dest == ALW). No transfer to an unverified "
          "counterparty is accepted. (SCOPE v1: single authorized destination; the Hook-native "
          "equivalent of a permissioned-DEX/verified-counterparty gate.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
