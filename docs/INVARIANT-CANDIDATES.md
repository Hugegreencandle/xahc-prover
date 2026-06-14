# Candidate invariants for xahc-prover

A sourced backlog of properties worth proving about Xahau Hooks, beyond the six we ship today
(spend-limit · dst-allowlist · guard-termination · state-monotonicity · no-double-spend ·
balance-conservation). Each is mapped to the bug class it kills, the engine work needed, and a
falsifiable demo idea — so we build the high-value ones first.

Methodology follows Trail of Bits **invariant-driven development** (state each as a Hoare triple:
*pre → command → post*) and ranks against the **OWASP Smart Contract Top 10 (2026)**, whose 2024
loss data puts **access control ($953M)** and **logic errors ($64M)** at the top.
Sources: trailofbits.com (invariant-driven development, 2025-02), owasp.org/www-project-smart-contract-top-10.

> Legend — **Now**: provable with the current engine. **Needs**: engine work first.
> All must obey the prover's prime directive: a false PROVEN is catastrophic → fail closed.

## Ranked backlog

### 1. Authorization / access control  ·  OWASP SC01 (#1, $953M) ·  **Now**
*accept on a privileged path ⟹ the originating account is the owner or in an allow-set.*
- Kills the top real-world bug class: a hook that gates a payout/admin action but lets the wrong
  account trigger it. Xahau-flavored: `otxn` account vs `hook_account`, a `hook_param` allowlist,
  or a `HookGrant`.
- Engine: already models symbolic `otxn_field(sfAccount)` + `hook_account` + params (this is how
  guardrail's `is_outgoing` works). Generalize to "accept ⟹ origin ∈ {owner, allow…}".
- Demo: `authz_ok` (REQUIRE origin==owner) → PROVEN; `authz_bug` (missing/typo'd check) →
  COUNTEREXAMPLE with an attacker account.

### 2. Input validation / fail-closed default  ·  OWASP SC05 ·  **Now**
*accept ⟹ every required field/param was present AND validated (no accept on an absent/default value).*
- The classic Xahau footgun: `hook_param` / `otxn_field` returns a **negative** (absent) code, the
  hook ignores the sign and treats the buffer as `0` → "limit 0 = allow", "missing flag = pass".
- Engine: host returns are already **symbolic** (we model absence). Add an invariant: no accept
  path is feasible where a required `*_ret < 0` (absent) yet the hook proceeded.
- Demo: `validate_bug` reads `LIM` but doesn't `REQUIRE` it present → an unset param yields a
  garbage/zero limit → COUNTEREXAMPLE.

### 3. No arithmetic overflow / wrap  ·  OWASP SC07+SC09 ·  **Now**
*accept ⟹ no amount/limit/fee computation on the path wrapped a 64-bit boundary.*
- Drops are `uint64`; `amount + fee`, `amount * rate`, accumulation in a loop can wrap. A wrapped
  value flowing to a limit check or an `emit` amount is a drain.
- Engine: Z3 bit-vectors make wrap detection exact — add an overflow predicate on each arithmetic
  result that taints a value reaching `accept`/`emit`. (Complements the existing div/rem trap model.)
- Demo: `overflow_bug` adds a tip to drops without a check → near-MAX input wraps → COUNTEREXAMPLE.

### 4. IOU / issued-amount conservation  ·  OWASP SC02 ·  **Now (in progress)**
*accept ⟹ Σ emitted issued-amount ≤ received, in XFL.*
- Extends native balance-conservation to trustline payments. Already underway (`prove_limit_iou`,
  `xfl.py`). The XFL flag maps are the soundness-critical part — verify vs `hookapi.h`, never guess.

### 5. Reserve safety  ·  return code -38 RESERVE_INSUFFICIENT ·  **Needs balance model**
*accept ⟹ the account isn't driven below its XAH reserve (base + owner-count × increment).*
- A hook that emits/pays without leaving reserve bricks the account. Needs the engine to model an
  account balance + reserve (currently we model the otxn amount, not the account's standing balance).

### 6. Foreign-state authorization  ·  OWASP SC01 / code -34 ·  **Needs foreign-state model**
*state_foreign_set on account A ⟹ a matching HookGrant from A exists.*
- Prevents a hook writing another account's state without authorization. Needs an engine model of
  `state_foreign` / `state_foreign_set` + the grant set (we model only own-account `state`/`state_set` today).

### 7. Emission-burden / no-runaway-emit  ·  OWASP SC10 (DoS) / codes -11,-13 ·  **Now (partial)**
*accept ⟹ emit count ≤ etxn_reserve AND emission generation/burden stays bounded.*
- We already prove the count bound (`nospend`). Extend to: a hook can't be driven (via `cbak`
  re-entry / emitted-txn loops) into an unbounded emission chain. Needs `cbak` + generation modeling.

### 8. Determinism / no insecure time-or-nonce dependence  ·  OWASP SC03+SC09 ·  **Now**
*a security decision (accept/limit) must not hinge on `ledger_seq`/`ledger_last_time`/`ledger_nonce`
in an attacker-influenceable way.*
- Niche but real: a hook that "unlocks" past a timestamp the submitter can nudge, or seeds a
  lottery from a guessable nonce. Engine models these host returns as symbolic already.

## Not applicable / low value on Xahau
- **Reentrancy (SC08)** — Hooks have no synchronous external call; the analog is emit→cbak,
  covered by #7. **Flash loans (SC04)** — no in-protocol flash-loan primitive. **Proxy/upgrade
  (SC10)** — closest analog is guarding `SetHook` itself (a narrow #1 variant).

## Build order recommendation
**#1 authorization** and **#2 input-validation** next — highest real-world loss class, both
provable with today's engine, both with clean one-character-bug demos (the kind that lands with
the audience). **#3 overflow** close behind (pure Z3, no new modeling). #4 is already in flight.
#5–#7 unlock after a balance/foreign-state/cbak modeling pass — schedule them as one "richer state
model" milestone.

Each shipped invariant should follow the repo pattern: a `prove_<name>.py` driver (fail-closed:
PROVEN/COUNTEREXAMPLE/INCONCLUSIVE), a correct + buggy hook pair in `hooks/`, a regression-test
row, and a README demo block. New bug classes found in the wild → new rows here.
