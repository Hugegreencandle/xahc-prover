# The invariant DSL

State a hook property in one line and check it with the generic prover, instead of
writing a Python driver:

```sh
python src/prove_dsl.py hooks/emit_inflate.wasm "accept implies emitted_total <= incoming_drops"
# ❌ COUNTEREXAMPLE — an accepting path violates the invariant
```

The DSL is an **additional** path, not a replacement: the hand `prove_*.py` drivers remain
the validated reference, and the DSL is cross-checked to reproduce their verdicts exactly
(see `tests/test_prover.py::test_dsl_equivalence_*`).

## The one rule: reject-unknown-loudly

A PROVEN verdict means the property holds for **every input in the engine's modeled scope**.
For that to be true, the predicate must be translated **completely and exactly**. So the DSL
**hard-rejects** (clear error, exit 1) any expression that references a quantity or operator
it can't model soundly — an unknown identifier, an unsupported operator, XFL arithmetic. It
**never** silently drops a term, treats an unknown as true, or weakens the predicate; a
weakened invariant would be a false PROVEN. The DSL also reuses the engine's exact fail-closed
gates: a symbolic-float over-approximation on an XFL term, an unsupported opcode, a hit unroll
bound, or an unparseable emit all force **INCONCLUSIVE**, never PROVEN.

## Verdicts (identical to the hand drivers)

| exit | meaning |
|---|---|
| 0 | **PROVEN** — no accepting path violates the predicate |
| 2 | **COUNTEREXAMPLE** — an accepting path violates it (concrete model exists) |
| 3 | **INCONCLUSIVE** — solver `unknown`, or an engine taint reached the predicate |
| 1 | **rejected** — the expression is malformed / references something unmodelable |

The checker asserts the **negation** of the predicate on each accepting path: all-UNSAT →
PROVEN, any-SAT → COUNTEREXAMPLE.

## Grammar

```
predicate := "accept" "implies" expr      // "accept implies" is sugar; you may also write expr alone
           | expr
expr       := expr "implies" expr          // right-assoc, lowest precedence
            | expr "or" expr
            | expr "and" expr
            | "not" expr
            | cmp
cmp        := add ( ("<=" | "<" | "==" | ">=" | ">" | "!=") add )?
add        := primary ( ("+" | "-") primary )*     // integer quantities ONLY
primary    := number | "xfl" "(" number ")" | "accept"
            | ident | ident "[" key "]" | "(" expr ")"
number     := decimal | 0xHEX
```

### Quantities (each maps to the engine's existing sound representation)

| term | meaning | engine representation |
|---|---|---|
| `incoming_drops` | native XAH amount of the triggering tx | masked native decode `Concat(amt[0]&0x3F, amt[1:])`, the TRUE drops (≤ a raw read) |
| `emitted_total` | sum of native drops the hook emits on this path | Σ of amounts parsed from the emitted Payment blobs |
| `emit_count` | number of `emit()` calls on this path | exact per-path count (loops unrolled) |
| `accept_code` | the code passed to `accept()` | the concrete accept code |
| `dest` | sfDestination of the triggering tx | 20 symbolic bytes |
| `param[NAME]` | hook parameter NAME | the param's symbolic bytes |
| `state_old[KEY]` / `state_new[KEY]` | state value read / written | the symbolic prior value / the written value |
| `iou_amount` | issued (IOU) amount, XFL | compared only via the engine's sound `float_compare` |

### Operators

- comparisons `<= < == >= > !=` — integer terms compared **unsigned** (the drops domain);
  byte terms (`dest`, `param[…]`, `state_*`) compared **structurally** for `==`/`!=`; XFL
  terms compared **only** through the sound `float_compare` ordering.
- arithmetic `+ -` — **integer terms only**. `+`/`-` on an XFL term is a hard reject (no raw
  XFL arithmetic).
- logic `and or not implies`.
- literals: integers (decimal or `0x…`), and `xfl(<int>)` for an XFL value (resolved through
  `xfl.py`).

Anything outside this set — an unknown identifier, an unsupported operator/token, XFL
add/subtract — is rejected before the engine even runs.

## Examples (each ≡ a hand driver, cross-checked)

```
accept implies emitted_total <= incoming_drops      # ≡ prove_conservation
accept implies emit_count <= 1                       # ≡ prove_nospend
accept implies incoming_drops <= param[LIM]          # ≡ prove_limit
accept implies dest == param[DST]                    # destination-allowlist style
accept implies state_new[NONCE] >= state_old[NONCE]  # monotonic state
```

## Honest scope

The DSL can only express properties over the engine's **modeled quantities** above. It does
not add modeling power — it's a thin, sound front-end to the same symbolic engine and the same
fail-closed guarantees. If you need a property outside these terms, it can't be stated (by
design) rather than stated unsoundly.
