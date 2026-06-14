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

## Status — MVP

Proves the **spend-limit** invariant on single-function hooks today (the class that
matters most for agent guardrails). Real symbolic execution of compiled WASM, not a
mock.

Roadmap:
- more invariants: destination allowlist, state monotonicity, **guard-termination**
  (prove no `GUARD_VIOLATION` for any input)
- multi-function hooks (inline local calls) → the full `agent_guardrail`
- an invariant DSL so you write the property in one line
- `xahc prove` integration so it's one command from source

Not audited. The spec you prove is only as good as the invariant you state.

## Run

```sh
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python src/prove_limit.py hooks/limit.wasm
```

MIT.
