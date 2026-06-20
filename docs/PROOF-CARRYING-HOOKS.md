# Proof-carrying Hooks — protocol-level verification by *checking*, not solving

The endgame for the verification stack, and the answer to "how does this actually *protect* a user?"
(the @ShortTheFOMO thread, 2026-06-20). Make verification part of **hook deployment** — but split the
work so the network never runs the prover.

## Why not "run the prover in the network"
The naive form — every hook must pass the prover or the network disables it — has three killers:
1. **Undecidability.** Symbolic execution + Z3 is undecidable; many safe hooks return INCONCLUSIVE.
   "Disable on not-pass" would brick legitimate, unanalyzable code. INCONCLUSIVE ≠ unsafe.
2. **"Pass" against *what*?** There's no universal "safe" — safety is relative to a *specified*
   invariant. You can't impose one invariant set on every hook.
3. **Consensus cost + determinism.** Running Z3 in consensus is expensive, can hang, and solvers
   aren't deterministic across versions → validators couldn't agree on the verdict.

## The fix — prove off-chain, *check* on-chain
Separate **proof-finding** (off-chain, undecidable, expensive, one-time — the prover) from
**proof-checking** (on-chain, decidable, cheap, deterministic — verify an attached proof). Finding a
proof is the hard part; checking one is easy. So:

- the developer proves the hook off-chain and **attaches a re-checkable proof** (the solver-free proof
  object + the anchor-bound manifest);
- a verifier **checks the proof** — `checkproof` re-derives the DRAT proof with a tiny checker, the SMT
  engine *and* solver out of the loop;
- **no proof = not verified (not banned); a valid proof = enforced.**

**Status — what exists vs what's proposed (read this before quoting it):** the off-chain half is BUILT
and runs today — `make-manifest --proof-object` (mint), the registry (anchor-bound binding keyed by
HookHash), `checkproof` (solver-free re-verify), and the deploy-gate demo below. The ON-CHAIN half —
the network checking the proof at SetHook — is a PROPOSAL, not current Xahau behaviour. It would
require a protocol amendment (new SetHook-time verification semantics), with all the real open
questions that implies (see "Cost & governance"). This doc + the demo show the off-chain gate working
and what the on-chain version could look like — not something the protocol does today.

## The gate (demo: `demos/proof_carrying_deploy.sh`) — an OFF-CHAIN gate today
A deploy policy declares a REQUIRED invariant. A candidate hook is **ADMITTED** only if it:
1. carries a PROVEN proof **bound to its exact bytecode** (the registry entry's anchor = this HookHash
   — a swapped/forked hook has a different hash → "deployed code is not proven code" → REJECT),
2. for the **required invariant** (proven for something else → REJECT),
3. whose proof object **re-checks independently** (`checkproof` → REJECT if it fails).
Otherwise REJECTED. The demo runs one policy against three hooks → ADMIT (proven), REJECT (no proof),
REJECT (unproven bytecode). The network never ran the prover — it only checked the proof.

## Enforce it TIERED, not universal
- Mandate a few **universal** cheap properties protocol-wide (terminate, no overflow-bypass).
- Let an **account or permissioned domain REQUIRE** proven hooks for sensitive surfaces (the money
  flows) — verified-or-rejected *for that surface*, without policing every hobby hook.
- App-specific safety stays **opt-in + attested** (the registry/badge).

## Cost & governance (the proposal — and its open questions)
Checking is *far* cheaper than proving (it's verification, not search), which is why an on-chain
check is plausible where an on-chain prover isn't. But "cheap" isn't "free", and a consensus
deployment has real unknowns I'm NOT hand-waving: the per-deploy checker cost (a DRAT proof can be
large), and **cross-validator determinism** — every validator must reach the identical verdict, so
the checker (drat-trim today; ideally a formally-verified one like cake_lpr) would need a pinned,
deterministic implementation. Those are the questions to answer before it's real, and they're
exactly Richard's domain.

Path: this is **not a hard fork of the chain's history**, but it IS a **protocol amendment** — new
SetHook-time verification semantics — which on Xahau goes through the **Governance Game** (the
amendment/voting mechanism). So: an amendment proposal, subject to governance, not something a vote
alone "switches on" without protocol work. Framed honestly, the pitch is: the off-chain primitive
works today; here's what putting the check on-chain would take.

## Honest residual
- Protects only against invariants someone **specified** (no spec = no protection).
- The proof checker (drat-trim today; cake_lpr — formally-verified — the floor) and the reducer
  encoding are the trusted base; the prover and the SAT solver are out of the loop for the check.
- A mutable hook can still be re-pinned by its owner — but a re-pin to un-proven code fails the gate
  (and `xahc-watch` flags PROOF_VOID live). See `docs/PROVABLE-UPGRADES.md`.
