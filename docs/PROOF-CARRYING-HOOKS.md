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
- the network **checks the proof at deploy** (SetHook) — `checkproof` re-derives the DRAT proof with a
  tiny checker, the SMT engine *and* solver out of the loop;
- **no proof = not verified (not banned); a valid proof = enforced.**

The enabling primitive already exists: `make-manifest --proof-object` (mint), the registry (anchor-bound
binding keyed by HookHash), `checkproof` (solver-free re-verify). The only missing step is the network
running the check.

## The gate (demo: `demos/proof_carrying_deploy.sh`)
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

## Cost & governance
Cost is priced by **fee** — cheap, because it's the *check*, not the proof (and bounded/deterministic).
This is **not a hard fork** — it's a **Governance Game proposal** (Xahau's on-chain governance,
Richard's lane). The safeguard lives in the protocol; the user is never "downwind" of an unverified
deploy.

## Honest residual
- Protects only against invariants someone **specified** (no spec = no protection).
- The proof checker (drat-trim today; cake_lpr — formally-verified — the floor) and the reducer
  encoding are the trusted base; the prover and the SAT solver are out of the loop for the check.
- A mutable hook can still be re-pinned by its owner — but a re-pin to un-proven code fails the gate
  (and `xahc-watch` flags PROOF_VOID live). See `docs/PROVABLE-UPGRADES.md`.
