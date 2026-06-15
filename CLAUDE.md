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
- `tests/test_prover.py` — regression matrix + soundness tests. Run after ANY engine change.
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
