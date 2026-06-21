# Consolidated Independent Audit — xahc-prover (2026-06-21)

Audit record for the 2026-06-21 session: 6 new invariants + drivers, 7 deployable money Hooks, 1 engine
change (record-only `hash_obs`), and a holistic pass over the engine trust root. Repo HEAD `469496f`.
This document is HONEST about what was and was NOT verified — read the Residuals section before quoting
any "audited" claim externally.

---

## Scope

New this session (the audit targets):
- Invariant drivers: `prove_trigger_lock`, `prove_time_release`, `prove_inactivity_release`,
  `prove_split_conservation`, `prove_hashlock`, `prove_quorum` (the 33rd–38th invariants).
- Money Hooks (spending authorities; Cron weak-TSH or claim/approval-triggered, no rollback):
  `subscription_ok`, `vesting_ok`, `deadman_ok`, `revenue_split_ok`, `revenue_split3_ok`, `escrow_ok`,
  `multisig_ok`.
- Engine: the record-only hash-observation capture in `prover.py` (for `hashlock`).
- Engine TRUST ROOT (whole): `prover.py` symbolic executor + `soundness.py` + `wasm.py` + `xfl.py`.

## Method (independence model + the discipline)

- TWO independent multi-agent passes, each a fresh skeptic per artifact, none being the agent that wrote
  or first-reviewed the code (run against a clean GitHub clone, not the author's working tree).
  - Pass 1 (#1): 14 reports — 6 drivers + 7 hooks + the engine diff.
  - Pass 2 (#2): 5 reports — engine subsystems (path-forking/feasibility, guard/loop-unrolling, host-fn
    models, soundness-gate + float/XFL, wasm-decode/arithmetic).
- Each adjudication REPRODUCED the key verdicts (ran the drivers, re-derived the bit-level claims)
  rather than trusting the per-artifact reports.
- DISCIPLINE: every flagged CRITICAL was VERIFIED at the source/bit level before any action. A false
  PROVEN dismissed is catastrophic; a false alarm acted on breaks correct code. Both failure modes were
  weighed explicitly.

## Results

### Layer 1 — drivers + hooks (14 artifacts)
- Verdict: **14/14 CLEAN. 0 genuine CRITICAL/HIGH.**
- Each driver returns PROVEN(0) on its OK hook AND COUNTEREXAMPLE(2) on its planted bug twin — the
  PROVENs are DISCRIMINATING, not vacuous.
- `unsound_gate` (fail-closed on float over-approx / unsupported opcode / hit unroll bound /
  analysis errors) is called before every PROVEN; vacuity guard (`n_emit_paths==0 -> N/A`) present.
- Engine recordings (`accepts_full` / `emits_on_accept` / `hash_obs_on_accept`) appended in lockstep;
  drivers re-check list-length alignment and refuse PROVEN otherwise. Byte-order (big-endian Concat),
  unsigned `ULT`, and 128-bit widening (no under/overflow in `last_seen+TMO`, the split sum) verified.

### Layer 2 — engine trust root (5 subsystems)
- Verdict: **SOUND. 0 genuine engine-level unsoundness.**
- Path-forking / feasibility: conservative (`feasible()` keeps paths on solver `unknown`); atomic accept
  snapshots; independent cloned constraint lists; `Terminal` blocks post-accept execution.
- Guard + loop-unrolling: exact per-path guard counter; bound-exhaustion sets `hit_bound -> INCONCLUSIVE`
  (paths not silently dropped).
- Soundness gate: all 39 drivers gate PROVEN behind `unsound_gate` (or a correct inline equivalent); the
  four flags are monotonic (never cleared).
- WASM decode + arithmetic: little-endian load/store; div/rem trap-forks to rollback; XFL extraction
  matches `xfl.py`; shift/rotate masking correct.
- Host-fn models: the one alleged bug refuted (see below).

## Verified false alarms (the discipline in action)

Five flagged CRITICALs across this session were VERIFIED as false alarms; in each case the proposed
"fix" would have BROKEN correct code. They are logged here because catching + verifying them — rather
than reflexively patching — is itself the soundness story.

1. Vesting CLF byte-order — claimed reversed; the PROVEN verdict itself disproved it (a swap would have
   spuriously CEX'd the OK hook).
2. Escrow post-emit `state_set` double-release — refuted: `XAHC_REQUIRE` calls `rollback()` and Xahau
   flushes emits only on ACCEPT, so emit + state commit atomically or roll back together.
3. Multisig same double-release intuition — same refutation; verified across all emit-then-record hooks.
4. Multisig symbolic-SGM "rejects sound hooks" — disproved (multisig_ok PROVENs); the suggested fix
   (drop SGM) would INTRODUCE a false PROVEN (junk prior-mask bits counting toward quorum).
5. Engine `_emit_drops` `0x3F` mask — claimed it clears amount bit 62 -> false PROVEN. Refuted three
   ways: the native STAmount wire format has bit63 = NOT_XRP, **bit62 = sign/positive flag**, bits[61..0]
   = drops magnitude (the hook encoder writes `0x40 | (drops>>56 & 0x3F)`; dev-reference line 246
   prescribes "mask byte0 with 0x3F"; `watch/ledger.py:25` `NATIVE_FLAG = 0x4000000000000000` and
   rejects `drops >= 2^62` as non-native). The proposed `0x7F` would decode every native amount as
   `drops + 2^62` — a catastrophic over-count. Left as `0x3F`.

## Honest residuals — what is NOT covered (read before quoting "audited")

- **No mechanized proof of the symbolic executor itself.** Soundness rests on (now multi-auditor) human
  review of Python, not a machine-checked metatheorem.
- **No differential testing against a second independent WASM engine.** WASM/host semantics are correct
  by inspection, not by a cross-execution oracle.
- **Host-function models are validated against docs/reference, not byte-for-byte against `xahaud`/
  `rippled`.** The `0x3F` native decode is self-consistent and matches the documented format, but
  "matches the deployed node's silicon" is assumed, not differentially tested.
- **No testnet / live-ledger validation.** These are pure symbolic proofs over the `.wasm`; nothing has
  been deployed, fired by a real Cron, or replayed against live state.
- **The 3-way revenue split is NOT fully certified.** `prove_emit_budget revenue_split3_ok.wasm`
  returns INCONCLUSIVE (solver `unknown` at the 20s timeout). It is certified for exact-distribution
  (split-conservation), cron-only (trigger-lock), and replay-safety (monotonic) — but has NO proven
  cumulative spend cap. The 2-way split and subscription DO get clean emit-budget PROVEN.
- **Independence is at the ARTIFACT level, not organizational.** Multiple independent passes per
  artifact with reproduced verdicts — but one engine, one toolchain, one party. No external/third-party
  audit, no second SMT backend.

## The honest label (use this; do not overclaim)

> "Six new safety invariants, machine-checked across drivers, hooks, and the engine trust-root by
> multiple independent passes with reproduced verdicts and zero genuine unsoundness found. Each proof
> catches its planted bug and refuses to certify what it can't model. The PROVENs are trustworthy
> against the engine's MODEL of Xahau — human-cross-checked and fail-closed, NOT yet machine-proven,
> NOT differentially tested against a live node, NO testnet runs; the 3-way split's spend-cap remains
> INCONCLUSIVE."

Phrasing rule: say "independently cross-checked" or "multi-pass internally audited." Do NOT say bare
"independently audited" to a customer (implies external/third-party). Do NOT say "formally verified
engine" or "testnet-validated" — neither is true yet.

## Open items / path to formal grade

1. [blocked: toolchain] Close the 3-way spend-cap — re-run `emit_budget` at a longer multi-emit solver
   budget; if still `unknown`, document the INCONCLUSIVE as honest scope, do not paper over it.
2. [blocked: toolchain] Testnet validation — deploy the 6 primitives, fire via Cron, replay with
   xahc-watch, confirm proof <-> on-chain behaviour.
3. [future] Mechanize the executor soundness (or differential-test against a second WASM engine) — the
   path from "cross-checked" to "formally verified." Largest remaining trust gap.
4. [cheap] Add a one-line comment at `prover.py` `_emit_drops` citing `ledger.py NATIVE_FLAG` + dev-ref
   line 246, so the `0x3F` mask stops being re-flagged by future auditors.

## Verdict

The 2026-06-21 work (38 invariants total; 6 new + 6 certified autonomous primitives' hooks) is
**rigorously cross-checked and honestly scoped**: drivers, hooks, and the engine trust-root independently
re-audited with zero genuine unsoundness, a fail-closed architecture confirmed end-to-end, and every
flagged CRITICAL verified rather than reflexively patched. It is **not** formally verified at the engine
level, **not** live-validated on testnet, and the 3-way split's spend cap is **not** proven. Sold under
those exact qualifiers, the work is honest and strong.
