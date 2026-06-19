"""SMT obligation export — the seam for verify-the-proof v2 (re-solve, don't re-run).

A driver proves `accept ⟹ P` by checking, for each accepting path, that the violation query
`path_constraints ∧ ¬P` is UNSAT. If `XAHC_EMIT_SMT=<dir>` is set, `emit_query` writes that exact
query (the solver's current assertions) as SMT-LIB2 at the moment the driver has established it is
UNSAT — so the file is EXACTLY the obligation that was proved. A third party then re-solves every
emitted file with ANY SMT solver and requires `unsat`, certifying the proof WITHOUT re-running our
symbolic engine (they trust their solver + our open encoder, not our run).

No-op unless XAHC_EMIT_SMT is set, so normal proving is unaffected.
"""
from __future__ import annotations

import hashlib
import os

_counts: dict = {}


def enabled() -> bool:
    return bool(os.environ.get("XAHC_EMIT_SMT"))


def reset() -> None:
    """Clear the per-process filename counters (tests run many proofs in one process)."""
    _counts.clear()


def emit_query(solver, invariant: str, kind: str = "path") -> None:
    """Write the solver's current (UNSAT) query as `<invariant>-<kind>-<n>.smt2` in XAHC_EMIT_SMT.

    Call this ONLY where the driver has established this path's violation query is unsat (i.e. the
    proof holds for the path) — so the emitted obligation matches the proof exactly. No-op if the
    env var is unset.
    """
    d = os.environ.get("XAHC_EMIT_SMT")
    if not d:
        return
    os.makedirs(d, exist_ok=True)
    key = (invariant, kind)
    n = _counts.get(key, 0)
    _counts[key] = n + 1
    safe = "".join(c if (c.isalnum() or c in "-_") else "_" for c in f"{invariant}-{kind}")
    header = (
        f"; xahc proof obligation — invariant={invariant} kind={kind} path={n}\n"
        f"; This query MUST be UNSAT. Re-solve with any SMT solver (z3/cvc5/bitwuzla) to\n"
        f"; certify the proof for this path without running the xahc symbolic engine.\n"
    )
    with open(os.path.join(d, f"{safe}-{n}.smt2"), "w") as f:
        f.write(header + solver.to_smt2())


def bundle_sha256(smt_dir: str) -> str:
    """Deterministic content hash of an obligation directory — binds the artifact to a manifest.

    sha256 over (filename, sha256(content)) for every .smt2, sorted by filename. Re-checkers
    confirm the directory they re-solve is the SAME artifact that was registered.
    """
    parts = []
    for name in sorted(os.listdir(smt_dir)):
        if not name.endswith(".smt2"):
            continue
        with open(os.path.join(smt_dir, name), "rb") as f:
            parts.append(name.encode() + b"\0" + hashlib.sha256(f.read()).digest())
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.hexdigest().upper()
