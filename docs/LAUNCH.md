# xahc-prover — launch material

Two formats below: a long-form writeup (blog/Medium) and an X thread. Both stick to
what the engine actually does — no invented endorsements, no metrics we didn't measure.

---

## Long-form writeup

### I built a tool that proves your Xahau Hook is safe. Then I tried to make it lie.

There's a hard wall in smart-contract security that almost nobody says out loud: you
cannot formally verify an arbitrary Ethereum contract. Not "it's expensive." Not
"the tooling isn't there yet." You *cannot* — the halting problem forbids it. EVM
contracts can loop forever, so the space of possible executions is infinite, and no
algorithm decides a property over an infinite space in finite time. Every EVM audit
you've ever read is, underneath the formalism, "we looked really hard and didn't find
anything." That is not the same as proof.

Xahau Hooks are different, and the difference is the whole story.

Richard Holland designed Hooks to be **not Turing-complete** and **guard-bounded**.
Every loop carries a `_g` guard budget; execution is guaranteed to terminate; the set
of reachable paths is **finite**. Most people read that constraint as a limitation —
"you can't even write a real loop." It is the opposite. A finite, terminating program
is a **decidable** one. The exact property that makes EVM unverifiable is absent in
Hooks by design. Bounded execution was always a superpower. Nobody had cashed it in.

**xahc-prover** cashes it in. It takes the *real compiled WASM* of a Hook, runs it
over symbolic inputs (the amount, the limit, the accounts are free variables, not
fixed numbers), forks at every branch, unrolls the bounded loops to their real guard
budget, and hands the whole path space to Z3 — an SMT solver. Then it asks one
question: *can any path that reaches `accept` violate the invariant?* If the answer is
no, that's a proof, over every possible transaction. If the answer is yes, Z3 produces
a model — a concrete transaction that breaks the hook. Not a warning. The attack.

#### The headline: the real guardrail is proven

The flagship target isn't a toy. It's `agent_guardrail` — a hook for putting layer-1
spending limits on an autonomous agent's account (pairs naturally with x402-style
agentic payments: the agent signs off-chain, the hook bounds it on-chain). It's
deployed on Xahau testnet. It has guarded loops, multiple branches, and an optional
destination lock. The prover proves **two independent invariants on it at once**:

```
✅ PROVEN [spend-limit] — never accepts an outgoing payment over LIM
✅ PROVEN [dst-lock]    — when a DST policy is set, an accepted outgoing payment
                          goes only to the allowed account
```

For all inputs. Not for a test vector — for the entire input space.

#### A proof that can't fail is worthless

So every invariant is falsifiable, and the failures are concrete. Flip one comparison
in the limit check and the prover hands back the exact transaction that breaks it —
`drops = 0x8000000000000000 > LIM`. The bug *and* the tx that triggers it.

The one I like best is a single-character bug. The destination-lock compare loops
`i < 19` instead of `i < 20`, so the last byte of the destination account is never
checked. A unit test catches this only if it happens to send to an account that
matches the allowed one in *exactly* 19 of 20 bytes — you would never write that test.
The prover finds it for every input:

```
❌ COUNTEREXAMPLE [dst-lock] — accepts a payment to a non-allowed destination:
   Destination=…FF   allowed(DST)=…00     (differs only in byte 19, the unchecked one)
```

That's the class of bug that ships to mainnet and quietly drains a wallet.

#### The math agrees with the chain

A symbolic engine is only worth something if its verdicts match reality. Every verdict
was confirmed on Xahau testnet — install the hook, send a 10-XAH payment against a
5-XAH limit, read the ledger's `engine_result`:

| hook | prover | ledger |
|---|---|---|
| correct | PROVEN safe | `tecHOOK_REJECTED` (rejects the over-limit pay) ✓ |
| inverted-compare bug | COUNTEREXAMPLE | `tesSUCCESS` (the ledger really does accept it) ✓ |

#### The part I'm actually proud of: I audited my own prover

A prover that says PROVEN when a hook is unsafe is worse than no prover — it launders
false confidence onto people's money. So before claiming anything, I attacked my own
engine across three lenses — symbolic-execution soundness, WASM opcode semantics, and
plain engineering — deliberately trying to make it certify a hook I knew was broken.

It worked. Five times. A sample:

- `clz`/`ctz`/`popcnt` shared one Z3 symbol, so two independent results were forced
  equal — that silently hid counterexamples.
- Shifts weren't masked to the operand width: `x << 32` evaluated to `0` instead of
  `x`, the opposite of what the WASM spec says.
- Division and remainder were modeled as total functions, but WASM *traps* on `÷0`
  and `INT_MIN/-1` — and a trap is a rollback. A trapping op could flow a value
  straight to `accept`.
- A host-call return was hardcoded, which constant-folded an entire branch out of
  existence — the prover "proved" code it never actually explored.

All five found, all fixed, all pinned by regression tests. The engine now **fails
closed**: three verdicts only — `PROVEN`, `COUNTEREXAMPLE`, `INCONCLUSIVE`. Every
construct it can't yet handle (un-inlined local calls, `call_indirect`, symbolic
memory addresses) *raises* — it never silently hands you a green checkmark it didn't
earn. I wrote the self-audit up in the README because for a tool like this, the
honesty about where it stops is the product.

#### The trifecta

This is the third leg of a set of tools for shipping safe Hooks:

| | tool | does |
|---|---|---|
| ✍️ write | **xahc** | author + compile a lint-passed hook |
| 🔬 simulate | **xahau-mcp** | run it against one live transaction |
| 🧮 prove | **xahc-prover** | prove it for **all** transactions |

Write → simulate one → prove all.

#### Honest scope

Single-function hooks today (the guardrail inlines to one function at `-O2`; larger
hooks will need explicit inlining). The spec you prove is only as good as the invariant
you state. Both limits are documented, not hidden. Open source, MIT.

Bounded execution was always the superpower. This is what it unlocks.

---

## X thread

**1/**
I built a tool that mathematically proves your Xahau money-Hook is safe — for *every*
possible transaction, not just the ones you tested.

Then I spent days trying to make it lie to me.

It lied 5 times. Here's the story. 🧵

**2/**
First, why this is even possible.

You can *never* formally verify an arbitrary Ethereum contract. The halting problem
forbids it — EVM loops can run forever, the path space is infinite. Every EVM "audit"
is really "we looked hard and found nothing." Not proof.

**3/**
Xahau Hooks are different.

Richard Holland made them not-Turing-complete + guard-bounded. Every loop has a `_g`
budget → execution always terminates → the path space is FINITE.

Everyone reads that as a limitation. It's the opposite. It makes Hooks DECIDABLE.

**4/**
xahc-prover symbolically executes the *real compiled WASM* over symbolic inputs.

Fork at every branch. Unroll the bounded loops. Hand the whole thing to Z3 (an SMT
solver) and ask: can any path that reaches `accept` break the invariant?

→ PROVEN, or a concrete counterexample.

**5/**
The headline: it proves the REAL `agent_guardrail` hook deployed on testnet.

Two invariants, one run, for ALL inputs:
✅ spend-limit — never accepts an outgoing payment over LIM
✅ dst-lock — when a destination policy is set, funds go ONLY to the allowed account

**6/**
A proof that can't fail is worthless. So every invariant is falsifiable.

Flip one comparison in the limit check → the prover hands back the exact attack tx:
`drops = 0x8000000000000000 > LIM`.

The bug, and the transaction that triggers it.

**7/**
Better — a ONE-character bug.

The dst-lock check loops `i < 19` instead of `i < 20`. Last byte of the destination
never checked. A test catches this only if it happens to send to an address matching
in exactly 19 of 20 bytes.

The prover catches it for every input:
`Destination=…FF  allowed=…00` (differs only in byte 19)

**8/**
And the math agrees with the chain.

Every verdict confirmed on Xahau testnet — install, send, read `engine_result`:
• correct hook → `tecHOOK_REJECTED` (rejects the over-limit pay) ✓
• buggy hook → `tesSUCCESS` (the ledger really does accept it) ✓

**9/**
Now the part I'm proud of.

A prover that says PROVEN when a hook is unsafe is worse than no prover. So I attacked
my own engine across 3 lenses — soundness, WASM opcode semantics, engineering —
trying to make it certify a hook I knew was broken.

**10/**
It worked. 5 times. A few:
• clz/ctz shared one symbol → forced two results equal → hid bugs
• shifts unmasked: `x << 32` gave 0, not x
• div/rem treated as total — but WASM TRAPS on ÷0, and a trap can reach `accept`
• a hardcoded host return folded a whole branch away

All found. All fixed. All regression-tested.

**11/**
The engine now fails closed. Three verdicts only: PROVEN / COUNTEREXAMPLE /
INCONCLUSIVE.

Everything it can't yet handle (un-inlined calls, call_indirect, symbolic memory
addrs) RAISES. It never hands you a green checkmark it didn't earn.

**12/**
This is the third leg of a trifecta for safe Hooks:
✍️ write — xahc
🔬 simulate — xahau-mcp
🧮 prove — xahc-prover

Write → simulate one → prove all.

Open source, MIT. Single-function hooks today; honest about where it stops.

Bounded execution was always a superpower. This is what it unlocks. 🔗
