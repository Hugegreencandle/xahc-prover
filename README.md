# xahc-prover — *Don't test your money-Hook. Prove it.*

A symbolic-execution engine that **mathematically proves** an Xahau Hook obeys an
invariant — for **every possible transaction**, not just the ones you tested — or
hands you the exact counterexample that breaks it.

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

This is the **actual `agent_guardrail` hook** deployed on Xahau testnet — multiple
guarded loops (the 20-byte outgoing-account check), the `otxn_type`/incoming
branches, and the optional destination lock — symbolically executed across every
path. **Two independent invariants are proven at once:**

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

### Verified on-chain

Every Prover verdict was confirmed on **Xahau testnet** — install the hook, send a
10 XAH payment against a 5 XAH limit, read the ledger's `engine_result`:

| hook | Prover | ledger |
|---|---|---|
| correct | PROVEN safe | `tecHOOK_REJECTED` (rejects the over-limit pay) ✓ |
| inverted-compare bug | COUNTEREXAMPLE | **`tesSUCCESS`** (the ledger really does accept it) ✓ |

The math and the chain agree.

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
- **Unsupported opcodes / `call_indirect` / un-inlined local calls RAISE** — they
  never silently drop a path.

This engine was **self-audited across three lenses** (symbolic-execution soundness,
WASM opcode semantics, engineering). Every false-PROVEN vector found was fixed:

- `hook_param` hardcoded length → dead-coded the DST branch → now **symbolic length**
- fixed loop-unroll bound → silently dropped paths → now **reads the real `_g` maxiter**, else INCONCLUSIVE
- `clz`/`ctz`/`popcnt` shared one symbol → forced independent results equal → now **fresh per occurrence**
- shifts unmasked → `x << 32` gave `0` not `x` → now **masked mod width** (WASM-faithful)
- div/rem treated as total → trap path could reach `accept` → now **÷0 / `INT_MIN/-1` model as rollback**
- i64 locals + the global section were guessed → now **decoded at real width / init value**

The remaining gaps (un-inlined local calls, `call_indirect`, symbolic memory
addresses) all **fail loud** (raise) — never a silent certificate. Regression tests
in `tests/`. Verdicts: `PROVEN` / `COUNTEREXAMPLE` / `INCONCLUSIVE`.

## Status

Proves two invariants — **spend-limit** and **destination-allowlist** — on the
**real `agent_guardrail`** (loops, branches, the optional `hook_param(DST)` lock),
the hook actually deployed on testnet. Real symbolic execution of compiled WASM,
not a mock. Both proofs are falsifiable: buggy variants yield concrete attack txns.

Roadmap:
- more invariants: state monotonicity, **guard-termination** (prove no
  `GUARD_VIOLATION` for any input)
- multi-function hooks via local-call inlining (the guardrail inlines to one fn at
  `-O2`; larger hooks will need explicit inlining)
- an invariant DSL so you write the property in one line
- `xahc prove` integration so it's one command from source

Not audited. The spec you prove is only as good as the invariant you state.

## Run

```sh
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python src/prove_limit.py hooks/limit.wasm
```

MIT.
