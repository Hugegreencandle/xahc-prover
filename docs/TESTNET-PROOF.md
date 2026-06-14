# Testnet proof — the ledger agrees with the prover

Empirical validation of xahc-prover verdicts on **Xahau testnet** (NetworkID 21338),
run 2026-06-14 with throwaway faucet accounts. Each prover verdict was reproduced
on-chain: install the hook, send the transaction the verdict describes, read the
ledger's `engine_result`. **All cases agree.**

Explorer: `https://explorer.xahau-test.net/tx/<hash>`

## Accounts (ephemeral testnet faucet keys; no value)
| role | address |
|---|---|
| **A** — `agent_guardrail`, params `LIM=5 XAH`, `DST=B` | `rH2RdFKtADfeQf6W7zXrZ7J7hsszaG76Ed` |
| **B** — allowed destination | `rGkfQn5bxTqKnKAJ3pc5NX4GRHEgeuDdbG` |
| **D** — disallowed destination | `rfWNuoWaFuNNz7BsnX6fgb1cubLpbgXiqy` |
| **E** — `termination_bug` | `rL3GUmiznY6zwPJdaWgwdQVLaJgCtBJa3J` |

Hook installs — **2 SetHook txs** (both `tesSUCCESS`):
- A ← agent_guardrail: `F70E84BAC6356D98D71922178887C1D4D4D23F7EEFBCE18CA079CDE36B08744C` (ledger 9673343)
- E ← termination_bug: `9C51886A10CAE3F849E91ED220D6E1D442BA5B9322FB28CC36D2FCF535CAE7D5` (ledger 9673346)

> **Hash count:** this page lists **8 transaction hashes total = 2 SetHook installs (above) + 6 result txs (the table below)**. Only the 6 result txs carry a prover verdict; the 2 installs are setup. So "6/6 agree" counts the 6 verdict txs, not the 2 installs.

## Results — prover verdict vs on-chain `engine_result` (6 result txs)
| # | case | prover verdict | tx hash | `engine_result` | HookReturnCode | ledger | agree |
|---|---|---|---|---|---|---|:--:|
| 1a | spend-limit, under (3 XAH → B) | PROVEN: under-limit accepts | `64D035B6CD3D0C668622641C4E0A8519FDD7E06A7D83968238127DC716F3D7ED` | `tesSUCCESS` | 0x3A | 9673349 | ✓ |
| 1b | spend-limit, **over** (10 XAH → B) | PROVEN: never accepts over-limit | `8AA5CB5C50F1CF76658CB836EA2ECA4ABCD56B3FE79BB31EE26AC5922BA4DA88` | `tecHOOK_REJECTED` | 0x2C | 9673352 | ✓ |
| 2a | dst-lock, allowed (→ B) | PROVEN: allowed dest accepts | `141017F1F0E907B7D7510B673FFFBF9D3F4BFE58EFC93A94DE9644D9A12DAC95` | `tesSUCCESS` | 0x3A | 9673354 | ✓ |
| 2b | dst-lock, **disallowed** (→ D) | PROVEN: only allowed dest | `425DE99C9264C4C49D0B517B6F8FCDE5BAC91C1F7838D52D5B7D715746165001` | `tecHOOK_REJECTED` | 0x37 | 9673357 | ✓ |
| 3a | guard-term, **overrun** (drops%256=64) | COUNTEREXAMPLE: GUARD_VIOLATION | `EE95C11490DB05CFF556A067367980E39E19F163CD899B1FD10FDE77C749B9A6` | `tecHOOK_REJECTED` | **0x8000000000000010** | 9673360 | ✓ |
| 3b | guard-term, in-budget (drops%256=4) | accepts within budget | `44A36D55E2B035929AC3C2986546D289152F53F9F48C364FC638AC418BE74207` | `tesSUCCESS` | 0x1A | 9673362 | ✓ |

**6/6 agree. No disagreement.**

### Reading the codes
- `tecHOOK_REJECTED` = a hook rolled the transaction back; `tesSUCCESS` = applied.
- The non-guard `HookReturnCode`s (0x3A/0x2C/0x37/0x1A) are the hooks' own `__LINE__`-based
  accept/rollback codes (e.g. 0x2C = the over-limit `XAHC_REQUIRE` line, 0x37 = the dst-lock
  line) — informational.
- **Case 3a is the decisive one:** `HookReturnCode = 0x8000000000000010`, **top bit set** =
  `GUARD_VIOLATION`. `termination_bug` has no `rollback()`, so the only way it can reject is
  the guard being crossed past its budget — exactly what `prove_termination` predicts for an
  amount whose last byte (the loop count) exceeds the guard's budget of 8.

## What this validates
The prover's `spend-limit`, `destination-allowlist`, and `guard-termination` verdicts are
not just internal to the Z3 model — the **live Xahau ledger produces the same accept/reject**
on the exact transactions the verdicts describe. The proof and the chain agree.

## Not run
- **IOU spend-limit (`limit_iou`)** — requires a testnet trustline + issuer setup (create
  issuer, establish a trustline to the hooked account, send an issued amount). Deferred as
  too involved for this pass; the native cases above already cross-check the engine end to
  end. The `prove_limit_iou` driver + its XFL model remain verified by the local test suite.

*Reproduce: the script that produced these (faucet → SetHook → Payment → read `engine_result`)
is `validate_trifecta.cjs`; it holds throwaway faucet secrets and is not committed.*
