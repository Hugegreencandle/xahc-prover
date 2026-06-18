# Root Integrity — proof-of-concept (for the EverArcade canonicalizer/root session)

**Target (EverArcade's next milestone):**
```
state_root  == SHA256(canonical(ArenaState))
world_hash  == SHA256(state_root || receipt_root || continuity_root)
```
using the byte-lexicographic-UTF-8 canonicalizer spec. The operational cert ladder (Replay ·
Federation · Restore · Migration) verifies this on the states actually RUN. **A proof verifies it for
ALL valid ArenaStates — including ones never executed.** That's the jump from a test ladder to a
protocol-level guarantee, and it's what this PoC demonstrates on a kernel shaped like Arena's.

## What's proven here
A canonicalizer-shaped kernel (`hooks/arena_root_kernel.c`): a canonical, fixed-layout, integer-only
ArenaState (`[tick:u64 | score:u64]`) → `HASH(canonical bytes)` → committed as `state_root`. Two
obligations, both PROVEN for ALL inputs:

| obligation | invariant | result |
|---|---|---|
| **(1) root commitment** — `state_root == HASH(canonical(state))` | `commitment` (audited) | **PROVEN** · forged-root twin → COUNTEREXAMPLE |
| **(2) determinism** — outcome independent of ledger entropy (nonce/seq/time) | `time-nonce` + `preview-faithfulness` (audited) | **PROVEN** |

Run:
```sh
python src/prove_commitment.py          hooks/arena_root_kernel.wasm      # PROVEN
python src/prove_commitment.py          hooks/arena_root_forge_bug.wasm   # COUNTEREXAMPLE
python src/prove_time_nonce.py          hooks/arena_root_kernel.wasm      # PROVEN
python src/prove_preview_faithfulness.py hooks/arena_root_kernel.wasm     # PROVEN
```

## How it maps to EverArcade — and the honest gaps
- **The hash is modeled as an uninterpreted function** (same input → same 32-byte digest; different
  inputs not provably equal). So `state_root == HASH(canonical)` is proven as a *binding* — a forged/
  stale/constant root can't equal the hash of the real state — WITHOUT modeling SHA internals.
  Collision resistance of SHA-256 is *assumed*, not proven. (Output width 32B already matches SHA-256.)
- **This PoC's state is canonical-by-construction** (fixed field order, integer-only). EverArcade's
  canonicalizer adds *dynamic keys sorted byte-lexicographically* — that ordering's determinism is the
  extra obligation: prove the encoder's output depends only on the state bytes (byte-derived order, no
  locale/collation, no float/time/rng). Bring the canonicalizer kernel and that becomes a determinism
  proof of the same shape as (2).
- **`world_hash` is the composed case**: `world_hash == HASH(state_root || receipt_root ||
  continuity_root)` — the same commitment property over the fixed-order concatenation of three roots,
  each itself honestly derived.
- **The proof certifies a WASM kernel.** The live runtime is JS; EverArcade's **replay certification**
  already proves JS ≡ replayed-roots, which closes the JS ≡ WASM gap. So the full surface is:
  **spec → WASM kernel → prover proof (1)+(2) → replay cert (JS ≡ WASM)**.

## The pitch in one line
Root Integrity Certification, done as a proof, turns *"the roots matched on every run we tried"* into
*"the root provably commits the canonical state for every valid ArenaState"* — a protocol-level
verification surface, not a runtime test. This PoC shows both obligations already prove out on an
Arena-shaped kernel with the shipped, audited invariants; the session wires it to the real
canonicalizer.
