"""xahc-watch — the fourth leg: bind a proof to a deployed hook and continuously attest it.

write (xahc) -> simulate one (xahau-mcp) -> prove all (xahc-prover) -> WATCH LIVE (xahc-watch).

A PROVEN verdict is static and bound to one WASM hash in one scope. Deployment can silently
void it (code drift via SetHook, a live tx in the prover's INCONCLUSIVE region, state/protocol
drift). This package binds a proof to a deployed hook and classifies every observed transaction
into exactly one of four buckets — CONSISTENT / VIOLATION / UNVERIFIED / PROOF_VOID — never an
implicit "ok". Silence is never safety (UNVERIFIED is watch's INCONCLUSIVE, and it is loud).
"""
