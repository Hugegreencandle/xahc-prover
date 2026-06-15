# xahc-prover — launch packet (ready to post)

Everything here is fact-checked against the shipped code + the on-chain validation
(docs/TESTNET-PROOF.md). No invented endorsements, no unverified numbers, no fabricated
hashes. Caveman mode does not apply to this file — it's external copy.

---

## A) X thread (final copy)

**1/**
I built the first tool that *mathematically proves* an Xahau money-Hook is safe — for every
possible transaction, not just the ones you tested.

Then I spent days trying to make it lie. It did, 5 times. I fixed every one.

Here's the story 🧵

**2/**
Today, Xahau Hooks that move money are secured by **hand review**. Even at XRPL Labs, the
treasury Hook was "reviewed by Richard Holland and other XRPL Labs members to ensure its
reliability."

There was no tool that *verifies* a Hook. Now there is.

**3/**
Why it's even possible: Richard made Hooks **not-Turing-complete** and **guard-bounded** —
every loop has a `_g` budget, so execution always terminates and the path space is finite.

That's the property that makes Hooks **decidable**. The halting problem says you can never
prove an arbitrary Ethereum contract. You can prove a Hook.

**4/**
xahc-prover symbolically executes the **real compiled WASM** over symbolic inputs, forks at
every branch, and asks Z3 (an SMT solver): can any path that reaches `accept` violate the
invariant?

→ PROVEN (for all inputs in scope), or the exact counterexample transaction.

**5/**
It proves **14 invariants** on real hooks, including the deployed `agent_guardrail`:
spend-limit · destination-lock · guard-termination · state-monotonicity · no-double-spend ·
balance-conservation · IOU limit · authorization · input-validation · overflow-safe limit ·
reserve safety · foreign-state authorization · time/nonce dependence · emission-burden
(emit_count ≤ etxn_reserve).

**6/**
A proof you can't falsify is worthless. So every invariant ships with a one-character-bug
twin the prover catches. Example — a dst-lock that loops `i < 19` instead of `i < 20` leaves
the last address byte unchecked. The prover returns the exact attack address. A test would
catch that 1-in-2^8 of the time.

**7/**
And the math agrees with the chain. I deployed the hooks on Xahau testnet and sent the exact
transactions the verdicts describe. **6/6 agree:**
• over-limit pay → `tecHOOK_REJECTED` ✓
• loop driven past its guard → `GUARD_VIOLATION` (HookReturnCode `0x80…10`) ✓
Real tx hashes in the repo.

**8/**
The part I'm proudest of: I audited my own prover across 3 lenses and found **5 false-PROVEN
bugs** — a shared symbol forcing two values equal, unmasked shifts, div/rem not trapping…

All fixed. It now **fails closed**: anything it can't model soundly returns INCONCLUSIVE,
never a green check it didn't earn.

**9/**
You don't even write Python to use it. State the property in one line:

`accept implies emitted_total <= incoming_drops`

The DSL hard-rejects anything it can't translate exactly — it would rather refuse than
quietly weaken your invariant into a false proof.

**10/**
It's the third leg of an open-source trifecta for safe Hooks:
✍️ write — xahc
🔬 simulate one tx — xahau-mcp
🧮 prove all inputs — xahc-prover

Write → simulate one → prove all. All MIT.

**11/**
Repos:
• xahc-prover — github.com/Hugegreencandle/xahc-prover
• xahc — github.com/Hugegreencandle/xahc
• xahau-mcp — github.com/Hugegreencandle/xahau-mcp

Built for the Xahau / Evernode community. Bounded execution was always a superpower — this
is what it unlocks.

**12/** (optional tag tweet — only if you want to)
cc @WietseWind @RichardAH and the Xahau devs — would love your eyes on the soundness model.

> Tag etiquette: credit Richard for bounding Hooks (factual). Never attribute a quote or an
> endorsement to anyone. Real people in your network: Wietse Wind, Richard Holland, Denis
> Angell, Tequ, Fomo — tag at your discretion, no words in their mouths.

---

## B) 60-second demo (shot-list / script to record)

Terminal, dark theme, large font. ~10s per beat.

1. **Title card** — "Don't test your money-Hook. Prove it." → cut to terminal.
2. `xahc prove agent_guardrail.wasm --invariant guardrail`
   → two green `✅ PROVEN` lines (spend-limit + dst-lock).
   VO: "This is the real guardrail hook. Proven safe — for every transaction, not the ones I tested."
3. Flip one comparison, rerun on the buggy build →
   `❌ COUNTEREXAMPLE drops=0x8000…`.
   VO: "Introduce a bug and it hands back the exact attack transaction."
4. `xahc prove termination_bug.wasm --invariant termination` → `❌ COUNTEREXAMPLE amt=…F0`,
   then cut to **explorer.xahau-test.net** showing that tx's `tecHOOK_REJECTED`.
   VO: "And the math agrees with the chain — verified live on testnet."
5. One-line DSL: `prove_dsl … "accept implies emitted_total <= incoming_drops"` → PROVEN.
   VO: "State any property in one line."
6. **End card** — the trifecta (write → simulate → prove) + the three repo URLs.
   VO: "I tried to make it lie. It did, five times. I fixed them all, in the open."

Capture tool: `asciinema` for crisp terminal, or screen-record + the explorer tab for beat 4.

---

## C) Submission blurb (grants / XRPL Commons / Xahau ecosystem)

> **xahc-prover** is the first formal-verification tool for Xahau Hooks. Because Hooks are
> not-Turing-complete and guard-bounded, their behaviour is *decidable* — so xahc-prover
> symbolically executes a Hook's compiled WASM and mathematically proves it obeys a safety
> invariant (spend limits, destination locks, guard-termination, state-monotonicity,
> no-double-spend, balance-conservation, authorization, input-validation, overflow, IOU
> limits, reserve safety, foreign-state authorization, time/nonce dependence, emission-burden)
> for **all** inputs in scope, or returns the exact transaction that breaks it. Six
> testnet cases — across three of the invariants (spend-limit, destination-lock,
> guard-termination) — were reproduced on the live Xahau testnet and agree with the prover. It's
> the third leg of an open-source trifecta — write (xahc), simulate (xahau-mcp), prove
> (xahc-prover) — MIT-licensed.

---

## D) Headline facts (all verifiable in-repo)
- First Hook verifier (a search for one returns only EVM tools).
- 14 invariants, each with a falsifiable buggy twin; 86 regression tests.
- 3-lens self-audit + a follow-up audit; **7 false-PROVEN vectors found + fixed**; fails closed.
- Honest scope discipline in action: the emission-burden invariant proves only the STATIC
  reserve-count bound (accept ⟹ emit_count ≤ etxn_reserve(n), `-13`); it returns INCONCLUSIVE —
  never PROVEN — for any hook exporting a `cbak` callback, because the dynamic re-entry emission
  chain is not modeled.
- 6/6 testnet cases agree (covering 3 of the invariants) — real hashes in docs/TESTNET-PROOF.md
  (e.g. over-limit reject `8AA5CB5C…BA4DA88`; guard-violation `EE95C114…49B9A6`, HookReturnCode
  `0x8000000000000010`).
- `call_indirect` executed; one-line invariant DSL; integrated as `xahc prove`.
- Honest scope: a PROVEN verdict is bounded to the engine's modeled subset; outside it the
  prover returns INCONCLUSIVE, never a false PROVEN.
