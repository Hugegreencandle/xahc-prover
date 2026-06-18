# xahc Proof Registry

The fifth leg of the toolchain: **write → simulate → prove → watch → REGISTER.**

Where `xahc-watch` binds *one* proof to *one* deployed hook at runtime, the Proof
Registry is the durable, queryable record across many hooks and many proofs:

> *For HookHash X — which invariants were proven, under what params, with what
> residual, by which prover commit and which attester — and is that record intact?*

Anyone holding a hook's bytecode can look up its proof status without re-running the
engine, and a deployer can ship the proof **with** the hook (proof-carrying hooks).

## Model

An append-only **transparency log** (JSONL). Each line is a `RegistryEntry` wrapping a
PROVEN `ProofManifest` (the same artifact `xahc prove`/`watch` already use; HookHash =
SHA-512Half of the bytecode, exactly the on-chain `HookHash`).

Entries are **hash-chained** (Certificate-Transparency style):

```
entry_hash = SHA-256( canonical{ index, prev_hash, manifest, pubkey, recorded_at } )
prev_hash(0) = 0*64 ;  prev_hash(i) = entry_hash(i-1)
```

Altering, reordering, or dropping any past entry breaks the chain from that point on,
and `verify` reports the exact entry. The current **head** hash is a single commitment
to the whole history — publish or anchor it (a Xahau tx memo) and the log becomes
externally pinned.

Each entry may carry an optional **Ed25519 attestation** (`pubkey` + `sig` over
`entry_hash`). Signing is available only if the `cryptography` package is installed;
without it the log is unsigned-but-tamper-evident (never a hard failure).

## CLI

```sh
xahc registry keygen --out attester.key        # generate an Ed25519 attester key
xahc registry add proof.json --key attester.key # register a PROVEN manifest (signed)
xahc registry check hook.wasm                   # resolve wasm -> HookHash -> status
xahc registry get <HookHash> --json             # status for a HookHash
xahc registry verify                            # re-check the whole chain + signatures
xahc registry list                              # per-hook rollup + head + integrity
xahc registry head                              # the head commitment (anchorable)
```

(Equivalently `python -m registry <cmd>` from the prover, with `src/` on `PYTHONPATH`.)
Store path defaults to `./proof-registry.jsonl` or `$XAHC_REGISTRY`; key may come from
`--key` or `$XAHC_REGISTRY_KEY`.

Exit codes: **0** ok / PROVEN · **2** UNPROVEN or TAMPERED/chain-broken · **3** usage.

## Fail-closed posture (soundness is the product)

- `add` **refuses** any non-PROVEN manifest (`exit_code != 0`) — a not-proven verdict
  can never be laundered into a registry record.
- `verify` enforces this again **on read**: a correctly hash-chained but non-PROVEN
  entry (i.e. the file was hand-authored around `add`) makes the whole log fail loudly,
  so `status` can never report PROVEN off it. Write-time *and* read-time fail-closed.
- A query for an unknown HookHash is **UNPROVEN** — loud, never an implicit pass.
  *Absence of a proof is not proof of safety.*
- A broken chain or a signature that does not verify is a loud **FAIL** (exit 2), and
  `status` for any hook returns **TAMPERED** rather than PROVEN while the chain is broken.

## Trust model — read this (what the registry does and does NOT guarantee)

The registry guarantees two things and deliberately not a third:

1. **Integrity** — entries have not been altered/reordered/dropped since recorded
   (the hash chain; verifiable against a published/anchored head).
2. **Attribution** — a signed entry was registered by the holder of a specific key.
   A verifier trusts only the attester public keys it chooses to pin.

It does **not** re-establish **proof validity**. The truth of "this hook satisfies
invariant I" comes from `xahc-prover` (symbolic execution, fail-closed). The registry
records that a proof was produced and by whom; it does not re-run the solver. A party
who signs a manifest is vouching for it under their key — so pin attester keys you
trust, and treat unsigned entries as only as trustworthy as the file's custodian.

### Tamper-evidence boundary (precise)

A hash chain detects edits *given a reference point*. An attacker who controls the
entire file can rebuild a fully self-consistent chain — but only re-signed under
**their** key, which changes the head. Therefore tamper-evidence is enforced by either:
pinning the original attester's public key (re-signed entries fail key-pinning), or
comparing `head` to an externally published/anchored value. Use at least one.

## Limitations

- **Concurrent writers**: `add` is read-then-append and not cross-process atomic. Single
  writer assumed; serialize writes if automating.
- **Manifest value domain**: manifests are integer/string/JSON; do not put floats in
  `params` (non-deterministic repr would weaken the canonical hash). The prover does not.
- **On-chain anchoring** of the head is supported by design (publish the head hash) but
  not yet automated into a SetHook/Payment memo — that's the natural next increment.
