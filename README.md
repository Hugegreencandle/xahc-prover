# xahc-prover — *Don't test your money-Hook. Prove it.*

A symbolic-execution engine that **mathematically proves** an Xahau Hook obeys an
invariant — over **every input in the modeled scope**, not just the ones you tested
— or hands you the exact counterexample that breaks it. When a hook falls outside
that scope the verdict is **INCONCLUSIVE**, never a false PROVEN (it *fails closed*).

**Scope of a PROVEN verdict (read this first).** "For all inputs" is precise but
*bounded*. A PROVEN result holds for: single-Payment hooks over **native and
IOU/issued (XFL) amounts**; **every otxn field** (sfAmount/sfAccount/sfDestination
have exact native models; any other field is read as fully symbolic content + a
symbolic present/absent length, so a hook gating on it is genuinely explored — never
skipped); `switch`/`br_table` (forked over all targets); `call_indirect` (dispatched
through the resolved function table — every type-matching target inlined, and
out-of-bounds / null-slot / type-mismatch indices trap to a rollback); loops within
their `_g` guard unroll bound; multi-function hooks via call inlining; and the modeled
subset of WASM. The cases that still force INCONCLUSIVE — nonlinear XFL float ops on
symbolic operands (and `float_log`/`float_root`, which have no sound model), an element
table the decoder can't resolve, a table slot pointing at a host import, recursion past
the depth cap, or symbolic memory addresses — **fail closed**. Within that scope the
"for all inputs" claim is real; outside it the prover refuses to certify.

```
✅ PROVEN  — for ALL inputs, the hook never accepts when drops > LIM.
❌ COUNTEREXAMPLE — the hook ACCEPTS an over-limit payment:
     drops = 0x8000000000000000 > LIM = 0x7FFFFFFFFFFFFFFE
```

## Why this is possible on Xahau (and not on Ethereum)

Hooks are deliberately **not Turing-complete** and **guard-bounded** — every loop
has a `_g` budget, so execution always terminates and the path space is **finite**.
Most people read that as a limitation. It's the opposite: it's the property that
makes Hooks **decidable**. The halting problem means you can *never* formally verify
an arbitrary EVM contract. You *can* verify a Hook — because Richard Holland bounded
it. xahc-prover turns that design choice into a superpower nobody had claimed.

The byte-level work a Hook does (decode an 8-byte amount, compare to a limit, check
an allowlist) is pure bit-vector arithmetic — exactly what an SMT solver (Z3)
decides. So we symbolically execute the **real compiled WASM** over symbolic inputs,
fork at every branch, unroll the (bounded) loops, and ask Z3 whether any path that
reaches `accept` can violate the invariant.

## The trifecta — safe Hooks, end to end

Three open-source tools, one workflow: **write → simulate one tx → prove all inputs.**

| stage | tool | what it does |
|---|---|---|
| **write** | [xahc](https://github.com/Hugegreencandle/xahc) | author + compile a safe Hook to clean, lint-passed WASM |
| **simulate one** | [xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp) | run the real bytecode against one live transaction |
| **prove all** | [xahc-prover](https://github.com/Hugegreencandle/xahc-prover) | prove an invariant holds for every input in scope — or return the counterexample |

## Demo

```sh
python src/prove_limit.py hooks/limit.wasm                  # correct hook  -> PROVEN
python src/prove_limit.py hooks/limit_buggy.wasm            # signed bug    -> counterexample @ 2^63
python src/prove_limit.py hooks/limit_buggy.wasm 600000000000000000   # ...but PROVEN SAFE under real XAH supply
python src/prove_limit.py hooks/limit_inverted.wasm 600000000000000000  # inverted bug -> reachable counterexample
```

The prover distinguishes a **theoretical** counterexample (needs more drops than
exist) from a **reachable** one — so you're not chasing bugs that can't happen.

### The headline: the *real deployed* guardrail is proven

```sh
python src/prove_guardrail.py hooks/agent_guardrail.wasm
# ✅ PROVEN — for ALL inputs, the guardrail never accepts an outgoing payment over LIM.
```

This is the **`agent_guardrail` hook** (a realistic spend-limit guardrail) —
multiple guarded loops (the 20-byte outgoing-account check), the
`otxn_type`/incoming branches, and the optional destination lock — symbolically
executed across every path. **Two independent invariants are proven at once:**

```
✅ PROVEN [spend-limit] — never accepts an outgoing payment over LIM.
✅ PROVEN [dst-lock]    — when a DST policy is set, an accepted outgoing payment
                          goes only to the allowed account.
```

Flip one comparison and the prover hands back the attack transaction:

```sh
python src/prove_guardrail.py hooks/agent_guardrail_buggy.wasm 600000000000000000
# ❌ COUNTEREXAMPLE [spend-limit] — ACCEPTS an over-limit OUTGOING payment: drops=… > LIM=15
```

The dst-lock proof is not decorative — it catches a **one-character off-by-one**.
A variant whose check loops `i < 19` instead of `i < 20` leaves the destination's
last byte unchecked; a test would only notice if it happened to send to an account
matching in *exactly* 19 bytes. The prover finds it for every input:

```sh
python src/prove_guardrail.py hooks/agent_guardrail_dstbug.wasm
# ❌ COUNTEREXAMPLE [dst-lock] — ACCEPTS a payment to a non-allowed destination:
#    Destination=…FF  allowed(DST)=…00      (differs only in byte 19, the unchecked one)
```

### Guard-termination — the invariant only a bounded VM can have

Every Hook loop must carry a `_g(id, maxiter)` guard; crossing it more than
`maxiter` times in one call kills the hook with `GUARD_VIOLATION`. The compiler
checks a guard is *present* — not that `maxiter` actually bounds the loop. A loop
whose trip count an attacker controls passes lint and dies on-chain. We prove it
can't happen — for all inputs:

```sh
python src/prove_termination.py hooks/agent_guardrail.wasm
# ✅ PROVEN — no guard is ever crossed past its budget; never dies with GUARD_VIOLATION.

python src/prove_termination.py hooks/termination_bug.wasm
# ❌ COUNTEREXAMPLE — guard 0x80000002 (budget 9) can be crossed > 9 times:
#    amt = …F0     (last byte 240 → the loop runs 240× against an 8-iteration budget)
```

The engine counts `_g` crossings 1:1 with the host — no unroll slack — so a
fixed-bound loop (`i < 20`) trips nothing and a data-dependent one terminates as a
violation the instant a feasible path exceeds its budget. This is the property the
halting problem *denies* you on Ethereum: you cannot prove an arbitrary EVM contract
even halts, let alone halts within budget. On Xahau you can.

### State-monotonicity — a stored value never moves backwards

Replay protection lives in hook state: a stored nonce / sequence / high-water mark
that must only ever increase. A hook that can be driven to overwrite it with a
*smaller* value is a replay/rollback bug. We prove it can't — modeling `state` (the
slot holds a symbolic prior value) and `state_set` (the written value), then checking
no accepting path lands the stored value lower:

```sh
python src/prove_monotonic.py hooks/monotonic.wasm
# ✅ PROVEN — every accepted write to hook state is never below its prior value.

python src/prove_monotonic.py hooks/monotonic_bug.wasm
# ❌ COUNTEREXAMPLE — accept writes state[NONCE] < its prior value (replay):
#    written = 0   prior = 1      (the missing strictly-increasing check)
```

### Emitted-value invariants — no-double-spend & balance conservation

Hooks can *emit* their own transactions. Two distinct ways that goes wrong, two
invariants — and they're orthogonal (the engine extracts the native amount from
each emitted Payment blob and counts the emits per path):

```sh
python src/prove_nospend.py hooks/emit_double.wasm
# ❌ COUNTEREXAMPLE — an accepting path emits 2 payments (policy allows 1)

python src/prove_conservation.py hooks/emit_inflate.wasm
# ❌ COUNTEREXAMPLE — emitted value exceeds incoming (value creation):
#    incoming = 130496 drops   emitted total = 1130496 drops
```

A forwarder that emits two half-payments **conserves value but double-spends**;
one that emits `incoming + X` **spends once but mints value**. Each invariant
catches exactly one and clears the other — `emit_double` passes conservation,
`emit_inflate` passes no-double-spend. Reaching the emit sites needs the engine to
**inline local function calls** (clang outlines a repeated `emit` builder at `-O2`);
that inliner is now in, with a depth cap that fails loud on recursion.

### The top real-world bug classes — authorization, input-validation, overflow

Mapped from the OWASP Smart Contract Top 10 (where access-control alone was **$953M** of
2024 losses) onto Xahau hooks — each a one-character bug the prover catches:

```sh
python src/prove_authz.py hooks/authz_bug.wasm
# ❌ COUNTEREXAMPLE — accepts a tx from a non-owner: origin=FF00…00  owner=00…00
#    (the hook read the accounts but forgot to REQUIRE origin == owner)

python src/prove_validate.py hooks/validate_bug.wasm
# ❌ COUNTEREXAMPLE — accepts even when required param LIM is ABSENT (fail-OPEN)

python src/prove_overflow.py hooks/overflow_bug.wasm
# ❌ COUNTEREXAMPLE — drops+tip wraps uint64 past the limit check:
#    true total = 18446744073728427264  >  LIM   (the 64-bit sum wrapped below it)
```

The `authz` / `validate` / `overflow` correct variants all prove `✅ PROVEN`. See
`docs/INVARIANT-CANDIDATES.md` for the sourced backlog these came from.

## State a property in one line — the invariant DSL

Instead of a Python driver, write the property directly:

```sh
python src/prove_dsl.py hooks/emit_inflate.wasm "accept implies emitted_total <= incoming_drops"
python src/prove_dsl.py hooks/limit.wasm        "accept implies incoming_drops <= param[LIM]"
```

Same verdicts/exit codes as the hand drivers (cross-checked on every fixture). The DSL is a
thin, **sound** front-end over the same engine: it only exposes quantities the engine models
exactly (`incoming_drops`, `emitted_total`, `emit_count`, `accept_code`, `dest`,
`param[…]`, `state_old/new[…]`, `iou_amount`), and **hard-rejects** any expression it can't
translate completely (unknown term, unsupported operator, XFL arithmetic) rather than
weakening it — a weakened invariant would be a false PROVEN. Grammar + scope:
[docs/INVARIANT-DSL.md](docs/INVARIANT-DSL.md). It adds no modeling power, only a one-line
way to state properties over what the engine already proves.

## Built into `xahc`

The prover is wired into the toolchain — one command from source, CI-friendly exit
codes (`0` PROVEN, `2` COUNTEREXAMPLE, `3` INCONCLUSIVE):

```sh
xahc prove myhook.c --invariant termination     # builds .c, then proves
xahc prove myhook.wasm --invariant conservation
xahc prove limit.wasm --invariant limit -- 600000000000000000   # forward args after --
```

Invariants: `limit` · `guardrail` · `termination` · `monotonic` · `nospend` · `conservation`.

`xahc prove` locates the prover via `$XAHC_PROVER_DIR` (or a sibling checkout) and
runs it against the built WASM.

### Verified on-chain (real testnet transactions)

The prover's verdicts were reproduced on **Xahau testnet** (NetworkID 21338): install
the hook, send the transaction the verdict describes, read the ledger's `engine_result`.
**All six cases agree** — full hashes, ledger indices, and explorer links in
[docs/TESTNET-PROOF.md](docs/TESTNET-PROOF.md).

| invariant | case | prover | on-chain `engine_result` | tx | agree |
|---|---|---|---|---|:--:|
| spend-limit | under-limit (3 XAH) | accept | `tesSUCCESS` | `64D035B6…F3D7ED` | ✓ |
| spend-limit | **over-limit (10 XAH)** | never accepts | `tecHOOK_REJECTED` | `8AA5CB5C…BA4DA88` | ✓ |
| dst-lock | allowed dest | accept | `tesSUCCESS` | `141017F1…12DAC95` | ✓ |
| dst-lock | **disallowed dest** | reject | `tecHOOK_REJECTED` | `425DE99C…65001` | ✓ |
| guard-termination | **loop overrun** | GUARD_VIOLATION | `tecHOOK_REJECTED`, `HookReturnCode=0x80…10` | `EE95C114…49B9A6` | ✓ |
| guard-termination | in-budget | accept | `tesSUCCESS` | `44A36D55…E74207` | ✓ |

Case 3 (overrun) is decisive: `HookReturnCode`'s top bit is set = `GUARD_VIOLATION`, and
`termination_bug` has no `rollback()`, so the kill can only be the guard the prover
predicted. (IOU/`limit_iou` not yet run on-chain — needs a trustline/issuer setup; see the
proof doc.)

## How it works

```
hooks/x.wasm ──▶ src/wasm.py   decode WASM -> nested instruction tree
              ──▶ src/prover.py symbolic interpreter (Z3 bit-vectors):
                                 • i32/i64 stack machine, concrete-address memory
                                 • fork at if / br_if, prune infeasible paths
                                 • unroll guard-bounded loops -> finite path set
                                 • model the Hook API (otxn_field, hook_param,
                                   hook_account, accept, rollback) symbolically
              ──▶ src/prove_limit.py  state the invariant, check every accept path
```

The symbolic inputs (`sfAmount` bytes, the `LIM` param, the account) are free
variables; a *spec* (`drops = bytes big-endian`, `accept ⟹ drops ≤ LIM`) is checked
against every accepting path. A SAT result is a concrete attack transaction.

## Soundness — the prover fails closed

A prover that says PROVEN when a hook is unsafe is worse than no prover. The engine
is built so it can never silently lie:

- **Loops unroll to the real `_g` guard bound**, read from the bytecode — not a
  guess. If a feasible path is ever dropped at the bound, the verdict is
  **INCONCLUSIVE**, never PROVEN.
- **Host-return lengths and uninitialized memory are symbolic** (worst case), so
  length-gated branches — like the guardrail's `hook_param(DST) == 20` lock — are
  actually explored, not constant-folded away.
- **`otxn_type`, all inputs, and every non-native otxn field are free symbolic** —
  over-approximating, the safe direction (can add spurious paths, never hide a real
  one). A hook gating accept on any field is explored, not skipped.
- **`switch`/`br_table` is executed** — forked over every labelled target plus the
  default (`idx >= n`), exhaustively and exclusively, so no real case is dropped.
- **`call_indirect` is executed** — dispatched through the decoder-resolved function
  table: every type-matching defined target is inlined under `idx == its slot`, and every
  other index (out-of-bounds, empty slot, type mismatch) traps to a rollback, exhaustively,
  so no reachable callee is dropped and a trap never reaches `accept`.
- **What can't be modeled fails closed** — an unresolvable element table, a table slot
  pointing at a host import, recursion past the depth cap, or a genuinely unmodeled opcode
  is recorded → verdict **INCONCLUSIVE**; unsupported decodes raise. Never a silent drop,
  never a PROVEN.

This engine was **self-audited across three lenses** (symbolic-execution soundness, WASM opcode
semantics, engineering) plus a follow-up adversarial audit. **7 false-PROVEN vectors found + fixed**,
each now covered by a regression test:

- `hook_param` hardcoded length → dead-coded the DST branch → now **symbolic length**
- fixed loop-unroll bound → silently dropped paths → now **reads the real `_g` maxiter**, else INCONCLUSIVE
- `clz`/`ctz`/`popcnt` shared one symbol → forced independent results equal → now **fresh per occurrence**
- shifts unmasked → `x << 32` gave `0` not `x` → now **masked mod width** (WASM-faithful)
- div/rem treated as total → trap path could reach `accept` → now **÷0 / `INT_MIN/-1` model as rollback**
- i64 locals + the global section were guessed → now **decoded at real width / init value**
- IOU balance-conservation reported a concrete emit as "conserved" **without comparing to the
  incoming amount** → now **fails closed to INCONCLUSIVE** for IOU emits (incoming-issued
  conservation is not modeled). *(found by the 2026-06-15 audit)*

The remaining gaps (symbolic memory addresses, unresolvable element tables,
table-slot-to-import, recursion past the depth cap) all **fail closed** — they drive the
verdict to INCONCLUSIVE, and unsupported decodes raise; never a silent certificate.
Regression tests in `tests/` (49). Verdicts: `PROVEN` / `COUNTEREXAMPLE` / `INCONCLUSIVE`.

The engine's hard-coded constants were cross-checked against ground truth
(`XRPLF/hook-macros` `hookapi.h` + `sfcodes.h`, and a `float_one` decode, 2026-06-14):
field IDs (`sfAmount`/`sfAccount`/`sfDestination`), `float_compare` flags
(`EQ=1`/`LT=2`/`GT=4`), the XFL bit layout (sign@62, exp 8-bit bias 97, mantissa 54-bit),
the XFL error sentinels, and guard arithmetic (`GUARD(N)→_g(id,N+1)`) — **zero
discrepancies**. A wrong constant here would be a false PROVEN, so they are verified, not
guessed.

## Status

Proves ten invariants — **spend-limit**, **destination-allowlist**,
**guard-termination** (no `GUARD_VIOLATION`), **state-monotonicity** (persisted
values never move backwards), **no-double-spend** (bounded emit count),
**balance-conservation** (emits ≤ received), **IOU/issued-amount limit** (XFL),
**authorization** (only the owner can trigger — OWASP SC01), **input-validation**
(no accept on an absent required param — SC05), and **overflow-safe limit** (a uint64
wrap can't bypass the limit check — SC07/09; scoped to the limit, not all arithmetic) — on
real compiled WASM including the
**`agent_guardrail`** spend-limit guardrail. Multi-function hooks supported via
local-call inlining. Not a mock. Every proof is falsifiable; buggy variants yield
concrete attack txns. All wired into `xahc prove`. Scope (native single-payment hooks;
all otxn fields modeled — native or symbolic; `switch`/`br_table` and `call_indirect`
executed; multi-function via inlining) is enforced by failing closed to INCONCLUSIVE outside it.

Roadmap:
- ~~invariant DSL~~ ✅ done — see below
- **richer state model** — reserve safety (`-38`), foreign-state authorization (`-34`),
  emission-burden via `cbak` — unlocks invariants #5–7 in `docs/INVARIANT-CANDIDATES.md`
- **`call_indirect` to host imports / unresolvable tables** — currently fail closed; model
  if a real hook needs them

Not audited. The spec you prove is only as good as the invariant you state.

## Run

```sh
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python src/prove_limit.py hooks/limit.wasm
```

MIT.
