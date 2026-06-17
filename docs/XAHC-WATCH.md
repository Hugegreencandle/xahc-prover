# xahc-watch — the fourth leg: observe in production

**write (xahc) → simulate one (xahau-mcp) → prove all (xahc-prover) → watch live (xahc-watch).**

A `PROVEN` verdict is powerful but **static and bound to one artifact**: "for all inputs *in
scope*, *this specific* WASM obeys invariant X." The moment a hook is deployed, three things can
silently void that guarantee:

1. **Code drift** — someone runs `SetHook` with different bytecode; the on-chain `HookHash` no
   longer matches the proven WASM. The proof now certifies code that isn't running.
2. **Scope gaps reached in the wild** — the prover *fails closed* to INCONCLUSIVE on regions it
   doesn't model. A live transaction can exercise exactly that region.
3. **State / protocol drift** — inductive invariants assume a valid base case; an out-of-band
   state write or an amendment changing host semantics can move the system out from under the proof.

`xahc-watch` **binds a proof to a deployed hook** and **continuously attests** that the binding
still holds and live transactions still obey the proven verdict.

## The four buckets (silence is never safety)

Every observed transaction the watched hook executed on lands in **exactly one** bucket:

| bucket | meaning | severity |
|---|---|---|
| **CONSISTENT** | the watched hook's own decision matches the proven predicate's expectation | quiet |
| **VIOLATION** | the watched hook **ACCEPTED** a tx the proof says it must **REJECT** | 🚨 critical, exit ≠ 0 |
| **PROOF_VOID** | the deployed `HookHash` ≠ the proven `HookHash` (a `SetHook` swap), **or** the bound account sent an in-scope payment and the proven hook did not run at all (removed/disabled) | 🚨 critical, exit ≠ 0 |
| **UNVERIFIED** | out of the proof's model: an IOU/undecodable amount, an undecodable tx body, an error/GUARD_VIOLATION hook exit, or the hook was *more* restrictive than the model predicted | ⚠️ loud — never "consistent" |

There is no implicit "ok". `UNVERIFIED` is watch's `INCONCLUSIVE`: loud, counted, never swallowed.
This mirrors the engine's rule — **SOUNDNESS IS THE PRODUCT** — on the runtime side.

**The decision is the *watched hook's own* `HookResult`, not the transaction's `engine_result`.**
A Payment runs several hooks (the sender's guardrail *and*, e.g., a Strong-TSH destination), and a
tx can also fail at apply-time for non-hook reasons. So the aggregate tx outcome is **not** this
hook's decision. The watcher reads the watched execution's `HookResult` (3 = accept, 0/4 = rollback;
`HookReturnCode` top bit = GUARD_VIOLATION → error), chain-validated per xahau-mcp's fidelity model.
A hook **accept** of a should-reject tx is a `VIOLATION` **regardless** of whether a downstream
actor or an apply-time `tec` happened to roll the transaction back; `engine_result` is used only as
a corroborating note.

## The no-fork rule

The accept/reject *expectation* comes from the **same predicate the prover proved**. The guardrail
rules (spend-limit `drops ≤ LIM`, dst-lock 20-byte equality) are defined once in
`src/watch/predicates.py` against an abstract backend, and evaluated two ways:

- the symbolic prover (`prove_guardrail.py`) uses the **z3** backend,
- the concrete watcher (`watch.py`) uses the **Python-int** backend.

If the watcher re-implemented the rule by hand and it drifted from the driver, the watcher would
certify a lie. `tests/test_watch.py` additionally asserts **predicate parity** across the two
backends (including the spend boundary and the byte-19 dst off-by-one).

## The proof manifest (the prove → watch seam)

The prover emits a small JSON the watcher consumes — no need to import the symbolic engine:

```sh
python src/prove_guardrail.py hooks/agent_guardrail.wasm \
    --emit-manifest g.proof.json --lim 5000000 --dst <20-byte-account-id-hex>
```

```json
{
  "invariant": "guardrail",
  "verdict": "PROVEN [spend-limit, dst-lock]",
  "exit_code": 0,
  "hook_hash": "531BD1D7…675BB20C",
  "params": { "LIM": 5000000, "DST": "ACB11D25…350ADC" },
  "scope_caveats": ["native XAH amounts only — IOU/issued amounts are out of model"],
  "network_id": 21338
}
```

- `hook_hash` = **SHA-512Half** (first 32 bytes of SHA-512) of the hook bytecode — the same digest
  xahaud exposes via `util_sha512h` and stores as `HookHash` in HookDefinition / HookExecutions
  metadata. The binding check compares it to the *deployed* hook's `HookHash`; if the preimage ever
  disagreed with xahaud the hashes would simply never match → every tx classifies `PROOF_VOID`
  (loud over-alert), **never** a silent pass. The assumption fails toward alarm, not comfort.
- **Fail closed:** a non-PROVEN verdict (exit ≠ 0) **cannot** be written as a manifest.

## Run it

```sh
# offline — replay a committed fixture (no network)
python -m watch g.proof.json --replay tests/fixtures/watch/guardrail_testnet.json --account <r-addr>
#   (run with PYTHONPATH=src, or `cd src && python -m watch …`)

# live — subscribe to the deployed account (network)
python -m watch g.proof.json --ws wss://xahau-test.net --account rH2RdFKtADfeQf6W7zXrZ7J7hsszaG76Ed
```

The live path **subscribes first, then backfills** the gap from the last-seen ledger via
`account_tx` — following the `marker` across **all** pages and de-duplicating by tx hash — so a
dropped websocket produces neither a silent gap nor a double-count. A failed backfill is surfaced
loudly and retried (never treated as "caught up"). `wss://` is required (a plaintext feed can be
MITM'd to suppress a VIOLATION; override with `XAHC_WATCH_ALLOW_INSECURE=1`). A malformed/crafted tx
can never crash the watcher — it fails closed to a loud `UNVERIFIED`. Exit is non-zero on the first
`VIOLATION` / `PROOF_VOID`.

## Validation — replayed against the real ledger

The spine is `tests/fixtures/watch/guardrail_testnet.json`: the **4 real `agent_guardrail` result
transactions** from [`TESTNET-PROOF.md`](TESTNET-PROOF.md) (account A on Xahau testnet, NetworkID
21338) — under-limit accept, over-limit reject, allowed-dest accept, disallowed-dest reject — with
their on-chain `engine_result` / `HookReturnCode`. The watcher's decode → predicate → compare path
reproduces all four agreements offline (**4/4 CONSISTENT**), and the fail-closed buckets are pinned:
a tampered accept → `VIOLATION`, an IOU amount → `UNVERIFIED`, a swapped hash → `PROOF_VOID`.

*(The other two `TESTNET-PROOF.md` result txns are `termination_bug` on a different account/hash —
outside this watcher's binding, by design.)*

## Scope (v1)

One invariant end-to-end: `agent_guardrail` (spend-limit + dst-lock), the only hook already
validated on live testnet. Other invariants reuse the same manifest + watch skeleton. Not yet in
v1: stateful slot-health (reading state slots to re-check inductive base cases) and automated
remediation — watch observes and alerts, it does not transact.

## Hardening — enterprise audit (2026-06-17)

A 5-dimension multi-agent audit (soundness/security/correctness/resilience/tests, each finding
adversarially verified) hardened the live path. Fixed: the classifier now reads the **watched
hook's own `HookResult`** instead of the aggregate `engine_result` (closing silent missed
VIOLATIONs when a multi-hook tx or apply-time `tec` rolled the tx back); an in-scope payment with
**no** execution of the proven hook → `PROOF_VOID` (not a silent `SKIP`); live `subscribe` message
bodies (`transaction` key) decode correctly and an undecodable body fails closed to `UNVERIFIED`;
backfill follows the `account_tx` `marker` across all pages (no silent truncation); `wss://`
enforced; inbound frames bounded; and crafted/malformed records fail closed instead of crashing the
monitor. The live transport now has direct offline tests (normalize / backfill-pagination /
subscribe-first). Report: `HQ/06-Technical/Audit_xahc-watch_2026-06-17.md`.
