# xahc-prover vs the OWASP Smart Contract Top 10 (2025)

**What this is.** [xahc-prover](https://github.com/Hugegreencandle/xahc-prover) symbolically
executes an Xahau Hook and either *proves* an invariant holds for **all inputs** or returns a
concrete **counterexample** — it never guesses. This page maps its invariants to the
[OWASP Smart Contract Top 10 (2025)](https://owasp.org/www-project-smart-contract-top-10/) and
is honest about what is **proven**, what is **out of domain**, and where the boundary lies.

**Read the verdicts literally.** A ✅ means a specific invariant is *machine-proven* for the
hooks that satisfy its contract — not a blanket "your hook is safe." Soundness is the product:
anything the engine cannot model (unsupported opcode, solver timeout, unbounded loop, symbolic
float) **fails closed to INCONCLUSIVE — never a false PROVEN.**

## Coverage matrix

| # | OWASP SC (2025) | xahc-prover | Invariant driver(s) | What is proven |
|---|---|---|---|---|
| SC01 | Access Control | ✅ Covered | `prove_authz`, `prove_foreign_authz` | accept ⟹ origin == owner; every `state_foreign_set` was grant-authorized (−34) |
| SC02 | Price Oracle Manipulation | ⚪ Out of domain | — | No price oracle / AMM primitive in the Hook model. DeFi-pricing concern, not a Hook-VM property |
| SC03 | Logic Errors | 🟡 Per-invariant | *(all drivers)* | Each invariant *is* a logic-error check for its property; there is no generic "all logic" catch — pick the invariant that encodes your intent |
| SC04 | Lack of Input Validation | ✅ Covered | `prove_validate`, `prove_validate_range` | accept ⟹ required param **present** AND **within its declared [LO, HI] bounds** |
| SC05 | Reentrancy | ✅ Covered | `prove_reentrancy` | accept ⟹ reserve-before-emit (no deferred accounting) + cap + no cbak refund-leak, across **both** `hook` and `cbak` entries |
| SC06 | Unchecked External Calls | ✅ Covered | `prove_unchecked_return` | accept ⟹ every failable `state_set` / `emit` return code was checked (no accept past a host-call failure) |
| SC07 | Flash Loan Attacks | ⚪ Out of domain | — | No lending / flash-loan primitive on Xahau Hooks in scope |
| SC08 | Integer Overflow & Underflow | ✅ Covered (scoped) | `prove_overflow` | a uint64 wrap cannot bypass the drops+tip limit check (the engine computes the true values **wide**, 128-bit) |
| SC09 | Insecure Randomness | ✅ Covered | `prove_time_nonce` | no accept decision hinges on `ledger_nonce` (a grindable/predictable value) |
| SC10 | Denial of Service | ✅ Covered | `prove_termination`, `prove_reserve`, `prove_emission` | no GUARD_VIOLATION / non-termination; balance never driven below reserve (−38); emit_count ≤ `etxn_reserve` (no −13) |

**Score: 7 covered, 1 per-invariant (SC03), 2 honestly out-of-domain (SC02, SC07).**
Every *in-domain, mechanically checkable* item has a prover. The only gaps are DeFi-specific
primitives — price oracles and flash loans — that **do not exist** in the Xahau Hooks execution
model; calling those "covered" would be dishonest.

## Why the Hook framing differs from EVM (and why that matters)

The OWASP list was written for EVM smart contracts. Two items mean something different on
Xahau Hooks, and the prover encodes the *Hook-native* threat rather than blindly porting EVM:

- **SC05 Reentrancy.** Hook invocations are **atomic** — state commits at invocation end, and
  `cbak` is a *separate later invocation* over already-committed state. Classic EVM mid-call
  reentrancy is therefore impossible. The real Hook bug class is **deferred accounting** across
  `emit → cbak` (record the spend only in cbak → a second `hook()` sees stale state →
  double-spend) and a **cbak refund leak**. `prove_reentrancy` proves the inductive step for
  both entry points: reserve-before-emit, the cumulative cap, and no-refund-past-reservation.
- **SC06 Unchecked External Calls.** On Hooks the "external calls" are host functions and
  emitted transactions. `prove_unchecked_return` proves that no accepting path ignores a
  failed `state_set` / `emit` — the failure mode where the intended state write or payment
  silently never happens yet the transaction is approved.

## How to run it

```sh
xahc prove <hook.wasm> --invariant <name>
#   authz | foreign-authz | validate | validate-range | reentrancy | unchecked-return
#   overflow | time-nonce | termination | reserve | emission | monotonic | nospend
#   conservation | limit | limit-iou | guardrail | period-budget
# exit 0 = PROVEN · 2 = COUNTEREXAMPLE · 3 = INCONCLUSIVE (fail-closed) · 1 = N/A
```

Every invariant ships with a **correct reference hook** that proves and a **buggy twin** (plus
adversarial twins for the subtle failure modes) that must produce a counterexample — the proof
that the proof *bites*. See `hooks/` and `tests/test_prover.py`.

---
*OWASP Smart Contract Top 10 (2025): SC01 Access Control · SC02 Price Oracle Manipulation ·
SC03 Logic Errors · SC04 Lack of Input Validation · SC05 Reentrancy · SC06 Unchecked External
Calls · SC07 Flash Loan Attacks · SC08 Integer Overflow & Underflow · SC09 Insecure Randomness ·
SC10 Denial of Service. Source: <https://owasp.org/www-project-smart-contract-top-10/>.*
