# Xahau Developer Reference (Hooks + Protocol)

A single consolidated, **current** reference for building on Xahau — assembled for the
Kairo Vault trifecta (xahc · xahau-mcp · xahc-prover). Compiled **2026-06-14** from the
live official docs (`xahau.network/docs`), the `xahaud` source, the Evernode docs, and
the verified xahc headers. Each section cites its source so you can re-check when the
protocol moves.

> Freshness note: Xahau versions by **date** (e.g. `2025.10.27-release+2405`), not semver.
> Amendments below are current as of compile date; for live status query a node with the
> `feature` command or check https://github.com/Xahau/xahaud.

---

## 0. Canonical sources

| Area | URL |
|---|---|
| Docs (live) | https://xahau.network/docs |
| Docs source | https://github.com/Xahau/Xahau-Docs |
| `xahaud` (node) | https://github.com/Xahau/xahaud |
| Hook API conventions | https://xahau.network/docs/hooks/functions/overview/hook-api-conventions |
| Return codes | https://xahau.network/docs/hooks/functions/overview/return-codes |
| SetHook | https://xahau.network/docs/protocol-reference/transactions/transaction-types/sethook |
| Amendments | https://xahau.network/docs/features/amendments |
| Weak/Strong (TSH) | https://xahau.network/docs/hooks/concepts/weak-and-strong |
| XRPL vs Xahau | https://xahau.network/docs/what-is-different |
| Data API | https://data.xahau.network/docs |
| Evernode docs | https://docs.evernode.org |
| Testnet faucet | `POST https://xahau-test.net/accounts` (returns funded account+secret) |
| Testnet RPC/WS | `https://xahau-test.net` / `wss://xahau-test.net` (NetworkID **21338**) |
| Mainnet | NetworkID **21337** |

---

## 1. Xahau vs XRPL — what's different

Xahau is a Layer-1 fork of the XRP Ledger with its own repo, amendments, and native token
**XAH**. Key divergences (source: *what-is-different*):

- **Hooks** — on-ledger WASM smart-contract layer attached to accounts (the headline; not on XRPL).
- **URITokens, not NFTokens** — first-class on-ledger NFTs (`URITokenMint/Burn/Buy/CreateSellOffer/CancelSellOffer`).
- **Remit** — WYSIWYG push payment (XLS-55): multi-currency + URIToken in one tx, auto-creates trustlines/reserves/destination.
- **Import / Burn-2-Mint** — bridge XRP→XAH; importing grants 2 XAH (B2M now gated by `ZeroB2M`).
- **Balance Rewards** — earn XAH for holding/using XAH (`ClaimReward`).
- **IOU Escrow & PayChannels** — escrow/paychannel support for issued tokens.
- **Date-based versioning**; **5-day** amendment majority window; **starting Sequence** = ripple-epoch account-creation time.
- **WASM/LLVM** build pipeline for hooks.

---

## 2. The Hooks execution model

Source: *hook-api-conventions*, *weak-and-strong*, *compiling-hooks*.

- A Hook is a WASM module with exactly **two** exportable entry points: `hook(uint32_t)` and
  optional `cbak(uint32_t)`. No other exports allowed (xahc `clean` strips strays).
- **Not Turing-complete + guard-bounded** → execution always terminates, path space finite.
  (This is the property xahc-prover exploits: Hooks are *decidable* where EVM is not.)
- **Memory**: a single stack frame, no heap, no dynamic allocation. Hooks pass *integers*
  (usually pointers into their own linear memory) to host functions.
- A Hook ends exactly one of three ways: **`accept`**, **`rollback`**, or **`error`**
  (e.g. `GUARD_VIOLATION`). `HookResult` in metadata is this 3-way outcome — *not* the same
  as `HookReturnCode` (the int passed to accept/rollback).

### `hook()` / `cbak()` context argument

The `uint32_t` arg carries execution context (source: *weak-and-strong*):

`hook(ctx)`: `0` = executed **strongly**; `1` = executed **weakly**; `2` = weakly after a
strong run triggered by `hook_again`.
`cbak(ctx)`: `0` = an emitted txn was accepted into a ledger; `1` = an emitted txn became
un-appliable (EmitFailure).

---

## 3. Hook API conventions

Source: *hook-api-conventions*.

- **Naming**: `[noun1]_[verb]_[noun2]`. Missing first noun ⇒ the namespace; missing verb ⇒
  `get`. So `state()` = get hook state, `state_set()` = set it, `state_foreign()` = get a
  foreign account's state.
- **All params** are `uint32_t / int32_t / uint64_t / int64_t` (pointers, lengths, XFLs, or values).
- **Param order**: `(write_ptr, write_len, read_ptr, read_len, …specifics)`. Some APIs only
  read, only write, or return by code alone.
- **All APIs return a signed int**: `< 0` = error (see §4); `>= 0` = success, usually the
  number of bytes written/read or an event count.

---

## 4. Return / error codes (complete)

Source: *return-codes*. Negative = error; `>= 0` = success/byte-count.

| Code | Name | Meaning |
|---|---|---|
| ≥0 | SUCCESS | bytes written/read or events performed |
| -1 | OUT_OF_BOUNDS | pointer/len outside the hook's memory |
| -2 | INTERNAL_ERROR | invariant trip (report it) |
| -3 | TOO_BIG | value larger than allowed space |
| -4 | TOO_SMALL | write_len too small for output |
| -5 | DOESNT_EXIST | object/item not found |
| -6 | NO_FREE_SLOTS | all 255 slots in use |
| -7 | INVALID_ARGUMENT | bad parameter |
| -8 | ALREADY_SET | once-per-execution param set twice |
| -9 | PREREQUISITE_NOT_MET | required prior call missing |
| -10 | FEE_TOO_LARGE | absurd fee computed |
| -11 | EMISSION_FAILURE | `emit()` failed (check node trace log) |
| -12 | TOO_MANY_NONCES | >256 `nonce()` calls |
| -13 | TOO_MANY_EMITTED_TXN | emitted more than `etxn_reserve` declared |
| -14 | NOT_IMPLEMENTED | API planned, not implemented |
| -15 | INVALID_ACCOUNT | bad 20-byte Account ID |
| -16 | **GUARD_VIOLATION** | a loop exceeded its declared `_g` maxiter → hook killed |
| -17 | INVALID_FIELD | serialized field not found |
| -18 | PARSE_ERROR | bad serialized object |
| -19 | RC_ROLLBACK | (internal) rollback event |
| -20 | RC_ACCEPT | (internal) accept event |
| -21 | NO_SUCH_KEYLET | keylet not found/invalid |
| -22 | NOT_AN_ARRAY | expected STArray |
| -23 | NOT_AN_OBJECT | expected STObject |
| -10024 | INVALID_FLOAT | NaN or XFL out of range |
| -25 | DIVISION_BY_ZERO | |
| -26 | MANTISSA_OVERSIZED | XFL mantissa must be 16 digits |
| -27 | MANTISSA_UNDERSIZED | |
| -28 | EXPONENT_OVERSIZED | XFL exponent must be ≤ 80 |
| -29 | EXPONENT_UNDERSIZED | XFL exponent must be ≥ -96 |
| -30 | XFLOVERFLOW | XFL op overflowed |
| -31 | NOT_IOU_AMOUNT | STAmount was XRP, expected IOU |
| -32 | NOT_AN_AMOUNT | STObject was not an STAmount |
| -33 | CANT_RETURN_NEGATIVE | would return negative (reserved for errors) |
| -34 | NOT_AUTHORIZED | foreign-state set without grant |
| -35 | PREVIOUS_FAILURE_PREVENTS_RETRY | after a NOT_AUTHORIZED |
| -36 | TOO_MANY_PARAMS | too many params for a later hook in chain |
| -37 | INVALID_TXN | serialized txn invalid |
| -38 | RESERVE_INSUFFICIENT | new state would exceed reserve |
| -39 | COMPLEX_NOT_SUPPORTED | would return a complex number |
| -40 | DOES_NOT_MATCH | two args required same type |
| -41 | INVALID_KEY | bad public key |
| -42 | NOT_A_STRING | buffer not nul-terminated |
| -43 | MEM_OVERLAP | write buffer overlaps read buffer |
| -44 | TOO_MANY_STATE_MODIFICATIONS | >5000 modified state entries across chain |
| -45 | TOO_MANY_NAMESPACES | >256 namespaces on the account |

---

## 5. Host function catalog (83 functions)

Complete list from the docs sitemap (`xahau.network/docs/hooks/functions/<category>/<fn>`).
**Core signatures** below are verified against the xahc headers (which wrap `xahaud`); for
the full per-function parameter tables, append the function path to the docs base URL.

### control
- `int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code)` — finish, apply the txn. Terminal.
- `int64_t rollback(uint32_t read_ptr, uint32_t read_len, int64_t error_code)` — finish, reject the txn (strong TSH only can block). Terminal.

### guard (control)
- `int32_t _g(uint32_t guard_id, uint32_t maxiter)` — declared at each loop head; the guard
  point may be crossed at most `maxiter` times per invocation, else `GUARD_VIOLATION` (-16).
  xahc's `XAHC_GUARD(N)` expands to `_g(id, N+1)` (the +1 absorbs the trailing condition check).

### developer-defined
- `int64_t hook(uint32_t ctx)` — entry point. `int64_t cbak(uint32_t ctx)` — emitted-txn callback.

### originating-transaction (otxn_*)
- `int64_t otxn_field(uint32_t write_ptr, uint32_t write_len, uint32_t field_id)` — read a field of the triggering txn.
- `int64_t otxn_type(void)` — the txn type code (e.g. Payment = 0).
- `int64_t otxn_id(uint32_t write_ptr, uint32_t write_len, uint32_t flags)` — txn hash.
- `int64_t otxn_slot(uint32_t slot_no)` — load the whole originating txn into a slot.
- `int64_t otxn_param(uint32_t write_ptr, uint32_t write_len, uint32_t kread_ptr, uint32_t kread_len)` — read an OTXN parameter.
- `int64_t otxn_burden(void)`, `int64_t otxn_generation(void)` — emission lineage.
- `otxn_json` — JSON view of the txn (newer). `meta_slot` — slot the txn metadata (weak hooks).

### hook-context
- `int64_t hook_account(uint32_t write_ptr, uint32_t write_len)` — the 20-byte account the hook runs on.
- `int64_t hook_hash(uint32_t write_ptr, uint32_t write_len, int32_t hook_no)` — a hook's definition hash.
- `int64_t hook_param(uint32_t write_ptr, uint32_t write_len, uint32_t kread_ptr, uint32_t kread_len)` — read a HookParameter by key.
- `int64_t hook_param_set(read_ptr,read_len, kread_ptr,kread_len, hread_ptr,hread_len)` — set a param for a later hook in the chain.
- `int64_t hook_again(void)` — request a weak re-execution after a strong run.
- `hook_skip(read_ptr, read_len, flags)` — skip another hook in the chain by hash. `hook_pos()` — this hook's position.

### state (key→value store on the account)
- `int64_t state(uint32_t write_ptr, uint32_t write_len, uint32_t kread_ptr, uint32_t kread_len)` — read state by key.
- `int64_t state_set(uint32_t read_ptr, uint32_t read_len, uint32_t kread_ptr, uint32_t kread_len)` — write/delete state.
- `int64_t state_foreign(write_ptr,write_len, kread_ptr,kread_len, nread_ptr,nread_len, aread_ptr,aread_len)` — read another account's state (namespace + accid).
- `int64_t state_foreign_set(...)` — write foreign state (requires a HookGrant; else `NOT_AUTHORIZED`).

### emitted-transaction (emit_*)
- `int64_t etxn_reserve(uint32_t count)` — declare how many txns will be emitted (required before `emit`).
- `int64_t etxn_details(uint32_t write_ptr, uint32_t write_len)` — write the EmitDetails blob into your tx buffer.
- `int64_t etxn_fee_base(uint32_t read_ptr, uint32_t read_len)` — required fee for the prepared emit blob.
- `int64_t emit(uint32_t write_ptr, uint32_t write_len, uint32_t read_ptr, uint32_t read_len)` — emit the prepared txn; writes the emitted hash.
- `int64_t etxn_burden(void)`, `etxn_generation(void)`, `etxn_nonce(write_ptr, write_len)` — emission accounting.

### float (XFL — see §8)
`float_set, float_sum, float_multiply, float_mulratio, float_divide, float_invert, float_negate,
float_compare, float_sto, float_sto_set, float_int, float_mantissa, float_exponent, float_sign,
float_one, float_root, float_log`.
- `int64_t float_set(int32_t exponent, int64_t mantissa)` — make an XFL.
- `int64_t float_compare(int64_t f1, int64_t f2, uint32_t mode)` — mode flags: `1` EQ, `2` LT, `4` GT (combinable).
- `int64_t float_sto(write_ptr,write_len, cread_ptr,cread_len, iread_ptr,iread_len, int64_t xfl, uint32_t field_code)` — serialize an issued STAmount (host-encoded).

### serialization (sto_*) — operate on serialized objects in memory
`sto_subfield, sto_subarray, sto_emplace, sto_erase, sto_validate, sto_to_json, sto_from_json`.
- `int64_t sto_subfield(uint32_t read_ptr, uint32_t read_len, uint32_t field_id)` — locate a field (returns packed loc).
- `int64_t sto_emplace(write,wlen, sread,srlen, fread,frlen, field_id)` — insert/replace a field. `sto_erase(...)` — remove one.

### slot (object slots, max 255)
`slot, slot_set, slot_clear, slot_count, slot_size, slot_type, slot_float, slot_subfield, slot_subarray, xpop_slot`.
- `int64_t slot_set(uint32_t read_ptr, uint32_t read_len, uint32_t slot_no)` — load an object (by keylet/txn hash) into a slot.
- `int64_t slot(uint32_t write_ptr, uint32_t write_len, uint32_t slot_no)` — dump a slot's content.

### utilities (util_*)
- `int64_t util_raddr(write,wlen, read,rlen)` — accid → r-address. `util_accid(...)` — r-address → 20-byte accid.
- `int64_t util_sha512h(write,wlen, read,rlen)` — SHA-512Half. `util_keylet(write,wlen, keylet_type, a..f)` — compute a keylet.
- `int64_t util_verify(dread,drlen, sread,srlen, kread,krlen)` — verify a signature against a public key.

### ledger
- `int64_t ledger_seq(void)` — current ledger index. `ledger_last_time(void)` — close time.
- `ledger_last_hash(write,len)`, `ledger_nonce(write,len)`, `ledger_keylet(...)`, `fee_base(void)`.

### trace-debug (no-ops on mainnet; visible in node trace log)
- `trace(mread,mrlen, dread,drlen, as_hex)`, `trace_num(mread,mrlen, int64_t number)`, `trace_float(mread,mrlen, int64_t xfl)`.

### websocket-apis (off-ledger helpers, not in-hook): `account_info`, `account_namespace`.

---

## 6. Field IDs (sfcodes) for `otxn_field` / `slot_subfield`

Field id = `(type_code << 16) | field_code`. Common values **verified against testnet** in
xahc-prover:

| Field | Hex | Type |
|---|---|---|
| sfAmount | `0x60001` | STI_AMOUNT (6) |
| sfFee | `0x60008` | STI_AMOUNT |
| sfAccount | `0x80001` | STI_ACCOUNT (8) |
| sfDestination | `0x80003` | STI_ACCOUNT |
| sfIssuer | `0x80004` | STI_ACCOUNT |
| sfTransactionType | `0x10002` | STI_UINT16 (1) |
| sfFlags | `0x20002` | STI_UINT32 (2) |
| sfSequence | `0x20004` | STI_UINT32 |

Native **XAH amount** decode: the 8-byte `sfAmount` has byte0 top bits as flags
(`0x80` = not-XRP, `0x40` = sign/positive). Mask byte0 with `0x3F`, then big-endian assemble
to get drops. (This is exactly what xahc-prover's amount specs do.)

---

## 7. Guard semantics (`_g`) — termination

Source: *return-codes* (-16), xahc `guard.h`.

- Every loop must call `_g(id, maxiter)` as the first non-trivial instruction at the loop head.
- `maxiter` = max times that guard point may be crossed **across the whole invocation** (not per entry).
  Crossing more → immediate `GUARD_VIOLATION` (-16), hook killed (→ rollback).
- `XAHC_GUARD(N)` ⇒ `_g(id, N+1)`. Nested loops must budget `outer*inner` (`XAHC_GUARD_NESTED`).
- This bounded design is why guard-termination is *provable* (xahc-prover counts crossings 1:1
  with the host and flags any input that can exceed budget).

---

## 8. XFL — issued-amount floating point

Source: *floating-point-numbers-xfl*, xahc `xfl.py` (verified: `float_one() == 6089866696204910592`).

- 64-bit "Integer Encoded Floating Point": sign bit, exponent, 54/55-bit mantissa.
- Mantissa must normalize to **16 decimal digits**; exponent in **[-96, 80]**.
- Sign bit is **inverted vs IEEE** (bit 62: 1 = positive). Issued STAmount value word has the
  not-XRP/NaN bit set; XFL clears it.
- Use the host `float_*` ops for all issued-amount math — never hand-roll XFL (off-by-one in the
  bit layout silently corrupts amounts). `fixFloatDivide` corrected a `float_divide` rounding bug.

---

## 9. SetHook transaction

Source: *sethook*. Installs/updates/deletes hooks. `Account` + `Hooks` array (one entry per
position in the chain; up to 10 hooks).

### Hook object fields
| Field | Type | Notes |
|---|---|---|
| `HookHash` | Hash256 | points at an existing `HookDefinition` (Install) |
| `CreateCode` | Blob | WASM bytecode hex (Create); empty + `hsfOVERRIDE` = Delete |
| `HookOn` | Hash256 | 256-bit **active-low** bitmask: which tx types **trigger** the hook (bit clear = fires) |
| `HookCanEmit` | Hash256 | (amendment **HookCanEmit**) same active-low semantics: which tx types the hook may **emit**; absent ⇒ may emit anything |
| `HookNamespace` | Hash256 | 32-byte state namespace (often `sha256(label)`) |
| `HookParameters` | Array | `{HookParameterName, HookParameterValue}` (Blob/Blob) |
| `HookGrants` | Array | `{HookHash, Authorize, Flags}` — authorize foreign-state writes |
| `HookApiVersion` | UInt16 | `0` |
| `Flags` | UInt32 | see below |

### Flags
`hsfOVERRIDE` (1) — replace/delete existing hook in slot · `hsfNSDELETE` (2) — delete a namespace's
state · `hsfCOLLECT` — collect-call (weak hooks pay their own way).

### Operations (diff of defaults/existing/specified)
**No-op** (empty), **Create** (CreateCode, new bytecode), **Install** (HookHash or existing
CreateCode), **Update** (no code; Namespace/Parameters/Grants change), **Delete** (CreateCode
empty + hsfOVERRIDE), **Namespace Reset** (hsfNSDELETE + HookNamespace; deletes ≤512 state
entries per tx, returns `tesPARTIAL` until done).

### HookExecutions metadata (in the originating txn's metadata)
`HookAccount, HookEmitCount, HookExecutionIndex, HookHash, HookInstructionCount,
HookResult (UInt8: accept/rollback/error), HookReturnCode (UInt64 — the int passed to
accept/rollback), HookReturnString, HookStateChangeCount`.
A `GUARD_VIOLATION` shows as `HookReturnCode` with the top bit set (`0x8000…`).

### Error cases
`tecDUPLICATE, tecDIR_FULL, terNO_ACCOUNT, terNO_HOOK, temDISABLED, temMALFORMED`.

---

## 10. Transactional Stake Holders (TSH) — weak vs strong

Source: *weak-and-strong*. Determines whose hooks run, when, and who pays.

- **Strong**: hook runs **before** the txn applies; **can `rollback`** the whole txn; the
  originating txn pays for execution.
- **Weak**: hook runs **after** the txn applies (sees metadata); **cannot rollback**; the TSH
  pays for its own execution and must have set the `asfTshCollect` account flag (collect-call).
- `IOUIssuerWeakTSH` amendment: currency issuers become weak TSH on txns touching their currency
  (if opted in).

### TSH reference (tx type → who, strength)
| Tx | TSH |
|---|---|
| Payment | **Strong**: Destination · **Weak**: non-issuer accounts rippled through |
| AccountDelete | Strong: Beneficiary (funds destination) |
| CheckCreate / EscrowCreate / PaymentChannelCreate | Strong: Destination |
| CheckCancel / EscrowCancel / PaymentChannelClaim / PaymentChannelFund | Weak: Destination |
| EscrowFinish | Strong: Destination |
| ClaimReward / Import | Strong: Issuer |
| Invoke | Strong: Destination |
| DepositPreauth | Strong: Authorized |
| SetRegularKey | Strong: the RegularKey account |
| SignerListSet | Strong: each signer (if active + hooked) |
| TrustSet | Weak: Issuer |
| OfferCreate | Weak: accounts whose offers were crossed |
| GenesisMint | (Strong account) Weak: each Destination |
| URITokenCreateSellOffer / URITokenBuy | Strong: Destination/Owner (+Issuer if tfBurnable) |
| URITokenBurn | Strong: Issuer if tfBurnable |
| AccountSet, OfferCancel, TicketCreate, SetHook, URITokenMint, URITokenCancelSellOffer | None beyond originator |

(Full OTXN×TSH matrices incl. URIToken burnable cases: see *weak-and-strong*.)

---

## 11. Xahau-specific transaction types

Source: *transactions*, *amendments*. Beyond the standard XRPL set:

- **Remit** (XLS-55) — push payment: multiple currencies + URITokens to one destination in one
  tx; auto-creates trustlines/reserves/destination; can mint a receipt URIToken; optional 3rd-party
  Hook `Inform`. No partial payments, no pathing.
- **URIToken*** — `URITokenMint`, `URITokenBurn`, `URITokenBuy`, `URITokenCreateSellOffer`,
  `URITokenCancelSellOffer` (Xahau's NFT model).
- **Import** — bridge/claim from XRPL (uses an XPOP proof); grants 2 XAH (B2M gated by `ZeroB2M`).
- **ClaimReward** — claim Balance Rewards (XAH for holding/using XAH).
- **Invoke** — a no-op-payload txn used purely to trigger a destination's Hook.
- **GenesisMint** (emitted) — genesis account mints + distributes XAH (`XahauGenesis`).
- **SetRemarks** — attach key-value remarks to ledger objects (`Remarks` amendment).
- **CronSet** — schedule future Hook self-invocations (`Cron` amendment; ≤256 repeats).
- **Clawback** — issuer revokes issued tokens (`Clawback` amendment).
- Common fields incl. **EmitDetails** (generation, burden, callback, parent hash) on emitted txns.

---

## 12. Amendments (current — the "what's new")

Source: *amendments* (compile date 2026-06-14). Process: >80% validator support for **5 days** → enabled at flag-ledger +2.

### Feature amendments
| Amendment | What it does |
|---|---|
| **Hooks** | core WASM smart-contract layer |
| **HooksUpdate1** | Hooks system improvements |
| **XahauGenesis** | genesis XAH minting via GenesisMint |
| **MultiSign** | SignerListSet / multi-signing |
| **DepositAuth** | DepositPreauth |
| **Remit** | XLS-55 push payment (multi-currency + URIToken) |
| **ZeroB2M** | disables burn-to-mint credit (Import still works for key sync/activation) |
| **Remarks** | key-value remarks on ledger objects (dynamic NFTs, simpler hook-state) → SetRemarks |
| **Touch** | forces all TSH into txn metadata (audit consistency) |
| **HookCanEmit** | adds `HookCanEmit` field controlling which tx types a hook may emit |
| **Clawback** | issuer token clawback (ported from XRPL) — *2025.7.9-release+1951* |
| **DeepFreeze** | deep-freeze trustlines/assets (ported) — *2025.7.9-release+1951* |
| **IOUIssuerWeakTSH** | IOU issuers as weak TSH on currency-touching txns — *2025.7.9-release+1951* |
| **Cron** | scheduled hook execution via CronSet/Cron objects (≤256 repeats) — *2025.10.27-release+2405* |
| **ExtendedHookState** | bigger hook-state values via `HookStateScale` (1–16; scale N ⇒ ≤256·N bytes, N reserve units) — *2025.10.27-release+2405* |

### Notable bug-fix amendments
`fixXahauV1` (namespace limit 256, hook-param size fee 1 drop/byte, URIToken fixes) ·
`fixXahauV2` (TSH cleanup, exec flags in sfHookExecutions, sfEmitNonce in sfHookEmissions) ·
`fixXahauV3` · `fixNSDelete` (introduces `tesPARTIAL`) · `fixFloatDivide` (float_divide rounding) ·
`fixReduceImport` · `fixProvisionalDoubleThreading` · `fixInvalidTxFlags` (*2025.10.27+2405*) ·
`fixCronStacking` · `fixPageCap` · `fix240819` · `fix240911` · `fix20250131` · `fixRewardClaimFlags`.

> Live status: `feature` RPC on a node, or https://github.com/Xahau/xahaud.

---

## 13. State, namespaces, reserves

Source: *state-management*, *namespaces*, *parameters*, ExtendedHookState amendment.

- State = per-account key→value (`uint256` key → ≤256-byte value at scale 1).
- **Namespaces**: 32-byte `HookNamespace` partitions state; unique namespace ⇒ no clobbering.
  ≤256 namespaces/account (`fixXahauV1`). Delete via `hsfNSDELETE` (amortized, `tesPARTIAL`).
- **HookStateScale** (ExtendedHookState): scale 1–16 ⇒ value cap `256 × scale` bytes and
  `scale` reserve units per entry; can increase scale but not decrease without deleting all state.
- Limits: ≤5000 modified state entries across the chain (`-44`), foreign-set needs a HookGrant (`-34`).

---

## 14. Emitted transactions

Source: emit_* docs, *transaction-common-fields*.

1. `etxn_reserve(n)` — declare emit count up front (emit fewer = ok, more = `-13`).
2. Build the txn blob in memory (xahc `XAHC_EMIT_PAYMENT` does canonical field ordering).
3. `etxn_details(ptr,len)` — write the EmitDetails (generation/burden/callback/nonce/parent).
4. `etxn_fee_base(blob,len)` — compute required fee, patch it into the blob.
5. `emit(out,outlen, blob,bloblen)` — emit; returns the emitted txn hash.

- Emitted txns carry `sfEmitDetails`; `cbak()` is later called with ctx `0` (accepted) / `1`
  (EmitFailure). `HookCanEmit` restricts emit-able tx types.
- `xahaud` enforces emission burden/generation to bound recursive emission.

---

## 15. Tooling & endpoints

| Thing | Where |
|---|---|
| Hooks Builder (web IDE) | https://hooks-builder.xrpl.org (and curated-tooling page) |
| Hooks Toolkit | https://hooks-toolkit.com |
| `server_definitions` | RPC method → field/type/tx-type codes for binary codec (use for serialization) |
| Data API | https://data.xahau.network/docs (supply, account, ledger-by-time) |
| Faucet (testnet) | `POST https://xahau-test.net/accounts` → `{account:{classicAddress,secret}, balance}` |
| Explorer | xahauexplorer.com / xahscan.com |
| Signing (Xahau-aware) | `xrpl-accountlib` (fetch `server_definitions` → `XrplDefinitions` → `sign`) |

---

## 16. Evernode (ecosystem)

Source: docs.evernode.org. Decentralized hosting marketplace for **HotPocket** DApps, settled on
Xahau via Hooks.

- **HotPocket** — the smart-contract/consensus engine running DApp instances; users connect via
  WebSocket; NPL (Node Party Line) for inter-node messaging; data persisted under consensus.
- **Sashimono** — host management software (registers a host, leases compute, heartbeats to Xahau).
- **Governance/Reputation hooks** — on-ledger governance game + host reputation scoring.
- SDKs: Evernode SDK / HotPocket SDK / `hpdevkit` / `evdevkit` / All-in-One kit.
- Hosts register on the **XRPL Hooks v3 testnet** for Evernode testnet.

## 17. XRPL Lending Protocol (XLS-66d) — Loan lifecycle, impair vs default

**XRPL-native (rippled), NOT a Xahau Hook.** Included here because Ward and cross-ledger
credit proofs depend on it. Source-verified against **`XRPLF/rippled @ ecf7f805c9`** (the merged
`featureLendingProtocol` amendment — the Devnet build family). Verified 2026-07-01.

**Objects & where fields live**
- `Loan` (`ltLOAN` 0x0089) — carries **`sfTotalValueOutstanding` (TVO)**, `sfPrincipalOutstanding`,
  `sfManagementFeeOutstanding`, `sfPaymentRemaining`, `sfNextPaymentDueDate`.
- `LoanBroker` — `sfDebtTotal`, `sfCoverAvailable` (first-loss capital).
- `Vault` — `sfAssetsTotal`, `sfAssetsAvailable`, `sfLossUnrealized`.
- TVO is a **per-Loan** field, not a broker/vault aggregate.

**Flags**
- Tx flags (`TxFlags.h`, on `LoanManage`, mutually exclusive, preflight-enforced):
  `tfLoanDefault=0x10000`, `tfLoanImpair=0x20000`, `tfLoanUnimpair=0x40000`.
- Ledger flags (`LedgerFormats.h`): `lsfLoanDefault=0x10000`, `lsfLoanImpaired=0x20000`,
  `lsfLoanOverpayment=0x40000`. Impaired+defaulted **coexist = 0x30000** (default only ADDS
  `lsfLoanDefault`, never clears impaired — and reads the still-set impaired flag to decide
  whether to reverse `sfLossUnrealized`).

**Impair** (`tfLoanImpair` → `impairLoan`, `LoanManage.cpp:300-339`): sets `lsfLoanImpaired`,
bumps vault `sfLossUnrealized`, moves `sfNextPaymentDueDate`. **Does NOT touch TVO** — the loan
still has a live outstanding balance (curable via `tfLoanUnimpair`).

**Default** (`tfLoanDefault` → `defaultLoan`, `LoanManage.cpp:148-297`):
- Zeros the Loan — `loanSle->at(sfTotalValueOutstanding) = 0;` (**line 279**) plus
  PrincipalOutstanding / ManagementFeeOutstanding / PaymentRemaining / NextPaymentDueDate. Sets
  `lsfLoanDefault`.
- TVO is declared **`SoeDefault`**, so assigning `0` routes through `makeFieldAbsent`
  (`STObject.h:761-764`) and the serializer skips it (`STObject.cpp:917-920`). **Set-zero ==
  the field is DELETED** → absent in `account_objects` / on the wire. (Full repayment via
  `LoanPay` closes the loan the same absent-on-zero way.)
- First-loss cover is drawn **atomically in the same tx**:
  `defaultCovered = min( min(minimumCover × coverRateLiquidation, totalDefaultAmount), CoverAvailable )`;
  broker `sfCoverAvailable -= defaultCovered` (line 272); `accountSend(broker → vault,
  defaultCovered)` (lines 290-296); vault `sfAssetsAvailable += covered`, `sfAssetsTotal -=`
  uncovered remainder (realized loss). `totalDefaultAmount = TVO − sfManagementFeeOutstanding`.

**Gotchas (rules of thumb for consumers like Ward)**
- **"TVO absent" ≠ defaulted.** Absence = *terminal* (defaulted OR fully repaid). Branch on the
  FLAG: `lsfLoanDefault` set ⇒ defaulted; TVO absent + `lsfLoanDefault` not set ⇒ repaid/closed;
  `lsfLoanImpaired` only (0x20000) ⇒ **still has a live TVO**.
- **No settlement gap.** The write-off and the cover waterfall are one atomic `tfLoanDefault` tx —
  you can't insert a step between default and cover-draw. The resolution "window" for an external
  verifier is the **impaired window** (after impair, before default) while TVO is still live.
- Cover draw can legitimately be **0** (broker has no `CoverAvailable` posted, or zero cover
  params) → `CoverAvailable` unchanged on default, which can look like "cover not deducted."

**Cites** (`XRPLF/rippled @ ecf7f805c9`): `src/libxrpl/tx/transactors/lending/LoanManage.cpp`
(`defaultLoan` 148-297, `impairLoan` 300-339, TVO clear @279, dispatch `doApply` 390-434);
`include/xrpl/protocol/LedgerFormats.h` (lsf flags); `include/xrpl/protocol/TxFlags.h` (tf flags);
`include/xrpl/protocol/STObject.h:761-764` + `src/libxrpl/protocol/STObject.cpp:917-920`
(SoeDefault → field-absent mechanism).

---

### Maintenance

Re-scrape when a new `*-release+NNNN` ships or an amendment flips. The high-churn sections are
**§5 functions** (new APIs like `otxn_json`, `xpop_slot`), **§12 amendments**, and **§11 tx types**.
Everything here was pulled live on 2026-06-14; signatures cross-checked against the xahc headers.
