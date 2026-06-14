# xahc-prover — *Don't test your money-Hook. Prove it.*

A symbolic-execution engine that **mathematically proves** an Xahau Hook obeys an
invariant — over **every input in the modeled scope**, not just the ones you tested
— or hands you the exact counterexample that breaks it. When a hook falls outside
that scope the verdict is **INCONCLUSIVE**, never a false PROVEN (it *fails closed*).

**Scope of a PROVEN verdict (read this first).** "For all inputs" is precise but
*bounded*. A PROVEN result holds for: native single-Payment hooks; the otxn fields
the engine models — **sfAmount, sfAccount, sfDestination** (every other field is
treated as absent); loops within their `_g` guard unroll bound; and the modeled
subset of WASM. It does **not** yet cover `br_table` (clang `switch`),
`call_indirect`, or IOU/XFL amounts — those force INCONCLUSIVE. Within that scope
the "for all inputs" claim is real; outside it the prover refuses to certify.

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

## The trifecta

| | tool | does |
|---|---|---|
| **write** | [xahc](https://github.com/Hugegreencandle/xahc) | author + compile a safe Hook |
| **simulate** | [xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp) | run it against one live transaction |
| **prove** | **xahc-prover** | prove it for **all** transactions |

Write → simulate one → prove all.

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
# ❌ COUNTEREXAMPLE — emits MORE than it received (value creation):
#    incoming = 130496 drops   emitted total = 1130496 drops
```

A forwarder that emits two half-payments **conserves value but double-spends**;
one that emits `incoming + X` **spends once but mints value**. Each invariant
catches exactly one and clears the other — `emit_double` passes conservation,
`emit_inflate` passes no-double-spend. Reaching the emit sites needs the engine to
**inline local function calls** (clang outlines a repeated `emit` builder at `-O2`);
that inliner is now in, with a depth cap that fails loud on recursion.

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

### Reproducing a verdict on-chain

Each Prover verdict is **reproducible on Xahau testnet** — install the hook, send
the transaction the verdict describes, and read the ledger's `engine_result`. The
table below is the *expected* ledger behavior each verdict predicts; run it yourself
to confirm:

| hook | invariant | Prover | expected ledger result (reproduce) |
|---|---|---|---|
| correct | spend-limit | PROVEN safe | `tecHOOK_REJECTED` (rejects the over-limit pay) |
| inverted-compare bug | spend-limit | COUNTEREXAMPLE | **`tesSUCCESS`** (the ledger accepts the over-limit pay) |
| `termination_bug`, drops%256=64 | guard-termination | COUNTEREXAMPLE | `tecHOOK_REJECTED`, `HookReturnCode` = guard-kill code |
| `termination_bug`, drops%256=4 | guard-termination | within budget → accept | **`tesSUCCESS`** |

To verify: install the hook, send a 10 XAH payment against a 5 XAH limit (and, for
the termination cases, an amount whose last byte is > 8 vs ≤ 8), then read
`engine_result`. The guard-termination prediction is that the attack amount (last
byte > 8) triggers a `GUARD_VIOLATION` while an in-budget amount goes through; the
hook has no `rollback()`, so a kill can only be the guard.

> **TODO:** paste the concrete testnet tx hashes / ledger indices here once a run is
> recorded. The verdicts above are reproducible, not yet pinned to published hashes.

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
- **`otxn_type` and all inputs are free symbolic** — over-approximating, the safe
  direction (can add spurious paths, never hide a real one).
- **Unsupported opcodes (`br_table`, `call_indirect`) and un-inlined local calls
  fail closed** — an unmodeled opcode is recorded and the verdict becomes
  **INCONCLUSIVE**; an unsupported decode/inline raises. Either way, never a silent
  drop and never a PROVEN.

This engine was **self-audited across three lenses** (symbolic-execution soundness,
WASM opcode semantics, engineering). Every false-PROVEN vector found was fixed:

- `hook_param` hardcoded length → dead-coded the DST branch → now **symbolic length**
- fixed loop-unroll bound → silently dropped paths → now **reads the real `_g` maxiter**, else INCONCLUSIVE
- `clz`/`ctz`/`popcnt` shared one symbol → forced independent results equal → now **fresh per occurrence**
- shifts unmasked → `x << 32` gave `0` not `x` → now **masked mod width** (WASM-faithful)
- div/rem treated as total → trap path could reach `accept` → now **÷0 / `INT_MIN/-1` model as rollback**
- i64 locals + the global section were guessed → now **decoded at real width / init value**

The remaining gaps (`br_table`, `call_indirect`, un-inlined local calls, symbolic
memory addresses) all **fail closed** — unmodeled opcodes drive the verdict to
INCONCLUSIVE, and unsupported decodes/inlines raise; never a silent certificate.
Regression tests in `tests/`. Verdicts: `PROVEN` / `COUNTEREXAMPLE` / `INCONCLUSIVE`.

## Status

Proves six invariants — **spend-limit**, **destination-allowlist**,
**guard-termination** (no `GUARD_VIOLATION`), **state-monotonicity** (persisted
values never move backwards), **no-double-spend** (bounded emit count), and
**balance-conservation** (emits ≤ received) — on real compiled WASM including the
**`agent_guardrail`** spend-limit guardrail. Multi-function hooks supported via
local-call inlining. Not a mock. Every proof is falsifiable; buggy variants yield
concrete attack txns. Wired into `xahc prove`. Scope (native single-payment hooks;
Amount/Account/Destination modeled; no `br_table`/`call_indirect`/IOU-XFL) is
enforced by failing closed to INCONCLUSIVE outside it.

Roadmap:
- **invariant DSL** — state the property in one line instead of a Python driver
- **IOU / issued-amount conservation** — extend balance-conservation to trustline
  (XFL `STAmount`) payments, not just native drops
- **`call_indirect` / function-table support** — the last un-inlinable call form
- further invariants: state-machine safety, reserve/fee correctness

Not audited. The spec you prove is only as good as the invariant you state.

## Run

```sh
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python src/prove_limit.py hooks/limit.wasm
```

MIT.
