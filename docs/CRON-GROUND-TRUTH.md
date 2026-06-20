# Xahau Cron — ground truth (from xahaud source, 2026-06-21)

Verified against `~/dev/xahaud/src/xrpld/app/tx/detail/{CronSet,Cron}.cpp`, `applyHook.cpp`,
`SetAccount.cpp`, `test/app/Cron_test.cpp`. The dev-reference omits Cron; this is the authoritative
basis for the provable-autonomous-primitives build. Cron + ExtendedHookState are LIVE on Xahau.

## CronSet transactor (ttCRON_SET = 93)
Three optional fields — `DelaySeconds` (D), `RepeatCount` (R), `StartTime` (S). Valid combinations
(CronSet.cpp:54-122):
- **D R S** — recurring cron: fires at StartTime, then every DelaySeconds, RepeatCount times.
- **- - S** — one-time cron at StartTime.
- **- - -** (no fields) — DELETE the account's cron.
- **D R -** invalid (StartTime required) · **D - S** / **- R S** invalid (D and R both-or-neither). → temMALFORMED.

Bounds (preflight):
- `DelaySeconds` ≤ 365 days (in seconds). >max → temMALFORMED.
- `RepeatCount` ∈ [1, 256]. 0 or >256 → temMALFORMED. (256 is per-cron-OBJECT, not lifetime.)
- `StartTime` is **chain time** = `parentCloseTime` seconds (NOT wall clock — deterministic). `0` = fire
  immediately/next. Else must be in the FUTURE (≥ parentCloseTime) and not too far ahead. (CronSet.cpp:138-157)

## How a cron FIRES (Cron.cpp) — the protocol auto-recurs
On each scheduled fire the PROTOCOL itself reschedules (Cron.cpp:131-176): reads the cron object,
`afterTime = lastStartTime + delay`, **erases** the object, and if `recur != 0` rewrites it with
`RepeatCount = recur - 1`, `StartTime = afterTime`. When `recur == 0` it stays erased (done).
**Consequence:** up to **256 periods are NATIVE — the hook does NOT re-arm.** Only to exceed 256 does the
hook emit a fresh CronSet (re-arm) — and THAT is the cron-stacking risk (`prove_cron`: ≤K re-arm/run;
mirrors the protocol's `fixCronStacking`).

## How the hook is invoked — WEAK TSH (the load-bearing safety fact)
`applyHook.cpp:76` — `case ttCRON: ADD_TSH(sfOwner, tshWEAK)`. When the cron fires (ttCRON pseudo-tx),
the **owner account's hook runs as a WEAK TSH**:
- **Weak TSH runs POST-apply and CANNOT roll back.** The cron pseudo-tx already applied; the hook can
  emit (or not) + write state, but cannot reject/undo. (Contrast strong-TSH, which can rollback.)
- The account must have **`asfTshCollect`** set → `lsfTshCollect` (SetAccount.cpp:476-488) to COLLECT
  weak-TSH invocations, i.e. for its hook to fire on the cron at all.
- **Why this forces verification:** an unattended, post-apply, no-undo money-mover means a logic bug
  EXECUTES irreversibly. You cannot rely on rollback. Safety (no overcharge, no double-pay, terminate)
  must be PROVEN inside the hook ahead of deploy — exactly the xahc-prover wedge.

## Other gotchas
- Hooked-account txns need a higher fee (the hook-execution surcharge) — emits from the cron hook
  likewise. Fail-closed if underfunded (telINSUF_FEE_P), don't assume a flat fee.
- No Batch (XLS-56) on Xahau → a cron hook canNOT do atomic multi-op; one emit per fire is the safe model.
- StartTime/scheduling is in ledger/chain time, so all timing invariants are deterministic (good for proofs).

## Implications for the provable-subscription Hook (v1 build)
Design: account sets a recurring CronSet (D=period, R=N≤256, S=first), `asfTshCollect` on; each fire the
weak-TSH hook emits ONE capped Payment to the allowed payee + decrements remaining in ExtendedHookState.
Invariants to PROVE (all already in the battery): `period-budget` (Σ over period ≤ cap), `conservation`
(no over-emit), one-emit-per-fire / `nospend` (no double-pay), `dst-lock` (payee fixed), owner-only
cancel (`authz`), and `cron` (≤K re-arm if extending beyond 256). Ship with `xahau-attest` cert.
