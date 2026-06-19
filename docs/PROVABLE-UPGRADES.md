# Provable Upgrades — closing "authorized ≠ safe" in the bootloader

The bootloader (Xahau discussion #759 / SetBoot) makes a Hook's boot target **upgradeable**. Two
links are already proven for all inputs (xahc-prover):

- **`bootloader`** (the gate) — `accept ⟹ candidate_hash == pinned_hash`: boot ONLY the pinned blob.
- **`boot-upgrade-authz`** (the re-pin) — `accept ⟹ origin == owner ∧ new_version > old_version`:
  only the owner re-pins, and only forward (no downgrade/replay to an older, vulnerable stage-2).

**The residual:** an *authorized* owner can re-pin to a NEW blob that is itself malicious or
regressed. Gate + authz both pass; the boot target is now unsafe. Authorized ≠ safe.

## The gate that closes it
A re-pin is only **certified** if the new blob **re-proves the named safety invariant(s) it claims**
(for an upgrade hook, `boot-upgrade-authz` — owner-only, strictly-monotonic; plus whatever else the
deployer requires, e.g. `limit`/`authz`). The guarantee is *scoped to the proven invariants*, not a
claim of total safety — a blob can pass the proven set yet be malicious in an unproven dimension, so
the invariant set must be chosen to match the risk:

1. **prove** the new blob's invariants (for all inputs, fail-closed).
2. **register** the proof — a signed entry keyed by the blob's on-chain HookHash. `make-manifest`
   is fail-closed: a non-PROVEN verdict **cannot** be written, so an unsafe blob **cannot enter the
   registry**.
3. **live**: `xahc-watch` fires **PROOF_VOID** the instant the deployed code ≠ the proven code — so
   an un-recertified upgrade is loudly flagged; `registry check` of an uncertified blob is UNPROVEN.

Net: **an upgradeable hook that is always provably-current, or loudly flagged.** A regressed
upgrade is *provably refused* — it fails the proof, so it can never be certified, and it shows
PROOF_VOID/UNPROVEN until it is (which an unsafe blob never can be).

## Run it
```sh
bash demos/provable_upgrades.sh    # prereqs: xahc + xahc-prover (XAHC, XAHC_PROVER_DIR)
```
It (1) certifies the current boot-upgrade hook (boot-upgrade-authz PROVEN, signed), then (2)
attempts a regressed upgrade (`boot_upgrade_downgrade_bug` — a downgrade-allowing re-pin): the proof
returns COUNTEREXAMPLE, `make-manifest` refuses it, and `registry check` reports UNPROVEN. The gate
holds.

## Scope / honesty
Per `prove_bootloader`: SetBoot stores the blob verbatim and the node verifies nothing — the
hash+version encoding is trusted; the proofs are of the gate/re-pin accept logic + the registry's
fail-closed certification. Bounded proofs, stated residual, never an unqualified "safe."

## The layers, together
`gate` (boot pinned) + `boot-upgrade-authz` (owner-only, forward-only) + **Proof Registry** (only a
PROVEN blob certifies, signed + re-checkable via `reverify`/`recheck`) + **xahc-watch** (PROOF_VOID
on deployed≠proven). The bootloader makes code upgradeable; this makes every upgrade **provably
consistent with the named invariants** (no unauthorized re-pin, no downgrade, + whatever else is
required) — re-proven for all inputs, independently re-checkable. Not a claim of total safety; a
guarantee exactly as strong as the chosen invariant set.
