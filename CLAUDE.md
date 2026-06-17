# xahc-prover — agent guide

Symbolic-execution engine (Python + Z3) that proves an Xahau Hook obeys an invariant for
ALL inputs, or returns a concrete counterexample. Third leg of the trifecta:
**xahc (write) → xahau-mcp (simulate one) → xahc-prover (prove all)**.

## Reference docs (read these before Xahau protocol questions)
- `docs/XAHAU-DEV-REFERENCE.md` — host fns, return codes, sfcodes, guard/XFL/emit semantics,
  SetHook, TSH, amendments. Live-scraped; cite it instead of guessing.
- `docs/XAHAU-RESOURCES.md` — repos/tools/libs/standards.
- Ground truth for VM behaviour: `Xahau/xahaud` and `XRPLF/hook-macros` (hookapi.h).

## Layout
- `src/prover.py` — the engine: symbolic WASM interpreter over Z3 bit-vectors. Path forking,
  guard-bounded loop unrolling, local-call inlining, host-fn models (otxn/state/emit/float/_g).
- `src/wasm.py` — WASM decoder → instruction tree.
- `src/xfl.py` — XFL (issued-amount float) constants/helpers.
- `src/prove_*.py` — one driver per invariant (see below). Each returns an exit code.
- `src/watch/` — **xahc-watch, the fourth leg** (write→simulate→prove→WATCH live). Binds a proof
  to a deployed hook + continuously attests it. `predicates.py` = the shared guardrail rule (one
  definition, z3 + concrete backends — `prove_guardrail.py` and the watcher CANNOT fork it);
  `manifest.py` = the prove→watch seam (HookHash=SHA-512Half(wasm); a non-PROVEN run can't emit a
  manifest); `ledger.py` = decode + live ws transport (lazy `websockets`); `watch.py` = classify
  each tx into CONSISTENT / VIOLATION / PROOF_VOID / UNVERIFIED (no implicit "ok"; UNVERIFIED is
  watch's INCONCLUSIVE). `python -m watch <manifest> --replay <fixture>|--ws <url>`. See
  `docs/XAHC-WATCH.md`. Deps: `xrpl-py` (addr codec) + `websockets` (offline tests need neither).
- `tests/test_prover.py` — regression matrix + soundness tests. Run after ANY engine change.
  (Folds in `tests/test_raw.py` + `tests/test_watch.py` under one runner.)
- `hooks/*.c` + `hooks/*.wasm` — demo hooks (correct + buggy variants). The `.wasm` fixtures
  are committed (gitignored by default; force-added) so tests run without a wasm toolchain.

## Invariants (driver → meaning), exit codes 0 PROVEN · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE
- `prove_limit` — accept ⟹ drops ≤ LIM
- `prove_limit_iou` — IOU/issued-amount limit
- `prove_guardrail` — the real deployed agent_guardrail: spend-limit + dst-allowlist
- `prove_termination` — no GUARD_VIOLATION for any input
- `prove_monotonic` — state never moves backwards (replay protection)
- `prove_nospend` — bounded emit count (no double-spend)
- `prove_conservation` — Σ emitted ≤ received (no value creation)
- `prove_authz` — accept ⟹ origin == owner (OWASP SC01)
- `prove_validate` — accept ⟹ required hook_param present (SC05)
- `prove_overflow` — a uint64 wrap can't bypass the drops+tip limit check (SC07/09)
- `prove_foreign_authz` — accept ⟹ every `state_foreign_set` was grant-authorized (SC01 / -34)
- `prove_reserve` — accept ⟹ balance − (emits+fees) ≥ base + owner_count*inc (-38)
- `prove_time_nonce` — no accept decision hinges on `ledger_nonce` (SC03/09)
- `prove_emission` — accept ⟹ emit_count ≤ `etxn_reserve(n)` (static reserve-count bound, `-13`).
  STATIC SCOPE ONLY: fails closed to INCONCLUSIVE whenever the module exports `cbak` (the dynamic
  re-entry emission chain is NOT modeled — never claim PROVEN there).
- `prove_period_budget` — STATEFUL inductive step: prior spent≤PLM ⟹ persisted spent'≤PLM
  (+ per-tx LIM + DST lock). Slot 0x01 = [periodStart|spent].
- `prove_validate_range` — SC04 deepening of `prove_validate`: accept ⟹ param VAL present AND
  LO_ ≤ VAL ≤ HI_ (within its declared bounds), not just present. Contract params VAL/LO_/HI_
  (8B BE each). N/A (1) if the hook doesn't read them.
- `prove_unchecked_return` — SC06: accept ⟹ every failable `state_set`/`emit` return was
  checked (no accept proceeds past a host-call failure). Opt-in engine flag
  `check_mutation_ret` makes those host fns return a SYMBOLIC may-be-negative code (default off,
  no other driver affected); a checked hook constrains it ≥0 on accept, an unchecked one leaves
  it free. N/A (1) if the accept path performs no such mutation.
- `prove_reentrancy` — SC05 cbak-safety INDUCTIVE step (the dynamic re-entry `prove_emission`
  fails closed on). Slot 0x01 = [reserved|spent], param LIM. Runs BOTH `hook` and `cbak` entries;
  proves reserve-before-emit (spent' ≥ spent+Σemit, no deferred accounting), cap (spent'≤LIM),
  no-refund-leak (spent' ≥ spent−reserved). N/A (1) if no cbak export or it's the PLM/PER
  period-budget contract. (Engine: `run(entry)` + `returns_full` capture normal-return paths.)
All are reachable via `xahc prove <hook> --invariant <name>` (in the xahc repo).

## SOUNDNESS IS THE PRODUCT — the one rule that matters
A false PROVEN (certifying an unsafe hook) is catastrophic. The engine **fails closed**:
- Anything it can't model soundly (unsupported opcode, solver `unknown`, hit unroll bound,
  symbolic float over-approximation) ⇒ INCONCLUSIVE (3), **never** PROVEN.
- `feasible()` treats Z3 `unknown` as "keep the path" (only `unsat` discards).
- Never "fix" the hard-coded XFL flag maps / FCMP_* / field IDs without re-verifying vs
  hookapi.h + testnet — a wrong constant = a false PROVEN.
When adding an invariant or host-fn model, add the fail-closed branch FIRST.

## Build / test / run
```sh
. .venv/bin/activate
python tests/test_prover.py                 # full regression — run after every change
python src/prove_guardrail.py hooks/agent_guardrail.wasm
```
- Building `.c → .wasm` needs a **wasm32-capable clang**: Apple clang does NOT have it.
  Use brew LLVM: `export PATH="/opt/homebrew/opt/llvm/bin:$PATH"` and
  `CC=/opt/homebrew/opt/llvm/bin/clang ~/Desktop/xahc/target/release/xahc build <f>.c -o <f>.wasm`.
- Committed `.wasm` fixtures mean you usually DON'T need to rebuild to run the proofs/tests.

## Testnet validation (when proving against the real ledger)
- Faucet: `POST https://xahau-test.net/accounts` (rate-limited ~60s). NetworkID **21338**.
- Sign SetHook/Payment with `xrpl-accountlib`: fetch `server_definitions` →
  `new lib.XrplDefinitions(sd)` → `lib.sign(tx, account, DEFS)`; submit via `xrpl-client`.
- A GUARD_VIOLATION shows on-chain as `tecHOOK_REJECTED` with `HookReturnCode` top-bit set.

## Conventions
- Commits: stage files BY NAME (never `git add -A` — it's hook-blocked). End messages with the
  Co-Authored-By Claude line. Conventional-commit style (`feat(...)`, `docs:`, `fix(...)`).
- Caveman mode is on in this session: terse chat, but code/commits/docs written normally.
- When proposing a hook is "safe", state which invariant under which spec — never unqualified.
