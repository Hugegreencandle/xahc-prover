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

### 5. Reserve safety  ·  return code -38 RESERVE_INSUFFICIENT ·  **DONE** (`prove_reserve`)
*accept ⟹ the account isn't driven below its XAH reserve (base + owner-count × increment).*
- A hook that emits/pays without leaving reserve bricks the account.
- Engine: models a symbolic standing balance + owner_count + reserve params (read as hook params
  BAL/OWNC/RSVB/RSVI), and tracks per-emit base fees. The driver checks no accepting path leaves
  `balance − (Σ emitted drops + Σ fees) < base + owner_count*inc` (computed wide, 128-bit, to
  catch a wrap in the hook's own headroom math). Emit fees are modeled as the same value
  `etxn_fee_base` returns, so outflow is neither over- nor under-counted.
- Fixtures: `reserve_ok` (checks headroom before emit) → PROVEN; `reserve_bug` (emits with no
  reserve check) → COUNTEREXAMPLE with a concrete (balance, owner_count, reserve).

### 6. Foreign-state authorization  ·  OWASP SC01 / code -34 ·  **DONE** (`prove_foreign_authz`)
*state_foreign_set on account A ⟹ a matching HookGrant from A exists.*
- Prevents a hook writing another account's state without authorization.
- Engine: models `state_foreign` / `state_foreign_set`. The host return is symbolic and MAY be
  the NOT_AUTHORIZED (-34) sentinel (the host returns it iff no HookGrant authorizes the write).
  A write is authorized iff the hook did NOT proceed-to-accept on the negative-return branch.
  Per accepting path the driver records every foreign-set and asserts each was granted; fails
  closed (INCONCLUSIVE) if the target account couldn't be modeled (non-20-byte).
- Fixtures: `foreign_authz_ok` (checks the return, rolls back when unauthorized) → PROVEN;
  `foreign_authz_bug` (ignores the return and accepts) → COUNTEREXAMPLE with the foreign account.

### 7. Emission-burden / no-runaway-emit  ·  OWASP SC10 (DoS) / code -13 ·  **DONE — STATIC PART ONLY** (`prove_emission`)
*accept ⟹ emit_count ≤ the count the hook passed to `etxn_reserve(n)`* (static, per-invocation).
- Emitting more than reserved is a runtime **-13 TOO_MANY_EMITTED_TXN** (the over-budget emit fails,
  leaving a partial/failed emission). Emitting at all without ever calling `etxn_reserve` (budget 0)
  is the same failure.
- Engine: `etxn_reserve(n)` now CAPTURES its argument — the FIRST call binds the budget (a second
  returns -8 ALREADY_SET and binds nothing, per xahaud once-per-execution semantics). Per accepting
  path the engine records `(emit_count, reserve_n, reserve_calls)`; `emit_count` is the exact tracked
  count (loops unrolled, calls inlined). The module's `cbak` export is detected (`has_cbak`).
- Driver (`prove_emission`): per accepting path, negate the invariant — ask Z3 whether
  `emit_count > reserved_n` is feasible under the path constraints. sat → COUNTEREXAMPLE; unknown /
  unsupported / hit-bound / float-overapprox → INCONCLUSIVE; all UNSAT → PROVEN (static bound).
- Fixtures: `emission_ok` (reserves 2, emits 2, no cbak) → PROVEN; `emission_bug` (reserves 1, emits 2)
  → COUNTEREXAMPLE; `emission_cbak` (exports cbak + emits) → INCONCLUSIVE.
- **SCOPE / explicitly NOT proven — fail closed on the dynamic case.** The candidate's second clause
  ("emission generation / burden stays bounded under `cbak` re-entry / emitted-txn loops") needs cbak
  + generation modeling the engine does NOT have. A `cbak` runs when an emitted txn settles and may
  itself emit / `hook_again`, growing the total burden across re-entries we don't model. So: **if the
  module exports `cbak`, the driver returns INCONCLUSIVE — NEVER PROVEN** for the unbounded-emission
  -chain property. A PROVEN is only ever emitted for cbak-free hooks, where the static per-invocation
  reserve bound IS the whole story. Do NOT describe a PROVEN here as "no runaway emit".

### 8. Determinism / no insecure time-or-nonce dependence  ·  OWASP SC03+SC09 ·  **DONE** (`prove_time_nonce`)
*a security decision (accept) must not hinge on `ledger_nonce` in an attacker-influenceable way.*
- Niche but real: a hook that seeds a lottery from a guessable/grindable nonce.
- Precise scope (intentionally NOT overclaimed): the driver proves NO accepting path's
  reachability depends on `ledger_nonce`. It does NOT flag `ledger_seq`/`ledger_last_time`
  deadlines (escrow-style time gates are legitimate). Engine: `ledger_nonce` reads return fresh
  symbolic bytes, all registered; `ledger_seq`/`ledger_last_time` are now symbolic too (seq was
  a concrete 1000 — a latent vacuous-result hazard). The dependence test substitutes the nonce
  symbols with a primed copy and asks whether an accept can hold under one nonce yet fail under
  another (an exact dependence query, no heuristics).
- Fixtures: `time_nonce_ok` (ledger_seq deadline, never reads the nonce) → PROVEN;
  `time_nonce_bug` (accepts/"wins" based on a nonce byte) → COUNTEREXAMPLE.

## Not applicable / low value on Xahau
- **Reentrancy (SC08)** — Hooks have no synchronous external call; the analog is emit→cbak, the
  STATIC count side of which is covered by #7 (the dynamic cbak chain is explicitly out of scope /
  fail-closed). **Flash loans (SC04)** — no in-protocol flash-loan primitive. **Proxy/upgrade
  (SC10)** — closest analog is guarding `SetHook` itself (a narrow #1 variant).

## Build order recommendation
**#1 authorization**, **#2 input-validation**, **#3 overflow** — SHIPPED. **#5 reserve safety**,
**#6 foreign-state authorization**, and **#8 time/nonce dependence** — SHIPPED (a "richer state
model" pass: symbolic standing balance + reserve params; `state_foreign[_set]` + grant-gated
return; symbolic `ledger_seq`/`ledger_last_time`/`ledger_nonce` with a nonce-dependence query).
**#7 emission-burden** — SHIPPED for the STATIC reserve-count bound (`prove_emission`: accept ⟹
emit_count ≤ etxn_reserve(n); fail-closed/INCONCLUSIVE whenever `cbak` is exported, since the dynamic
re-entry chain is unmodeled). Remaining: **#4 IOU conservation** (in flight) and the **dynamic #7
cbak-re-entry generation bound** (needs cbak + generation modeling — deliberately deferred, never
faked with a false PROVEN).

Each shipped invariant should follow the repo pattern: a `prove_<name>.py` driver (fail-closed:
PROVEN/COUNTEREXAMPLE/INCONCLUSIVE), a correct + buggy hook pair in `hooks/`, a regression-test
row, and a README demo block. New bug classes found in the wild → new rows here.
