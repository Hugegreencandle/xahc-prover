"""Re-solve exported SMT proof obligations with an independent solver (verify-the-proof v2).

Each `.smt2` in the bundle is a violation query the prover decided UNSAT (the proof for one
accepting path). Re-solving every file and requiring `unsat` certifies the proof WITHOUT running
the xahc symbolic engine — you trust your SMT solver + the open encoder, not our run.

Fail-closed: anything other than `unsat` for any file (sat, unknown, parse error, solver missing)
FAILS the recheck. Optionally bind to a registered artifact via its bundle sha256.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from smt_export import bundle_sha256


def _solve_z3(path: str) -> str:
    try:
        import z3
        s = z3.Solver()
        s.from_string(open(path).read())
        return str(s.check())  # 'sat' | 'unsat' | 'unknown'
    except Exception as e:  # parse error / solver failure -> fail closed
        return f"error:{type(e).__name__}"


def _solve_cvc5(path: str) -> str:
    exe = shutil.which("cvc5")
    if not exe:
        return "error:cvc5-not-installed"
    try:
        out = subprocess.run([exe, "--lang", "smt2", path], capture_output=True, text=True, timeout=120)
        first = (out.stdout or out.stderr).strip().splitlines()
        return first[0].strip() if first else "error:no-output"
    except Exception as e:
        return f"error:{type(e).__name__}"


def recheck_dir(smt_dir: str, solver: str = "z3", expect_sha256: str | None = None) -> dict:
    if not os.path.isdir(smt_dir):
        return {"ok": False, "reason": f"not a directory: {smt_dir}", "results": []}
    files = sorted(n for n in os.listdir(smt_dir) if n.endswith(".smt2"))
    if not files:
        # An empty bundle is NOT a pass — there is nothing certified. Fail closed.
        return {"ok": False, "reason": "no .smt2 obligations in bundle", "results": []}

    # Bind to the registered artifact if a hash is expected: re-solve the SAME obligations.
    actual_sha = bundle_sha256(smt_dir)
    if expect_sha256 and actual_sha.upper() != expect_sha256.upper():
        return {"ok": False, "reason": "bundle sha256 mismatch — not the registered artifact",
                "expected": expect_sha256.upper(), "actual": actual_sha, "results": []}

    solve = _solve_z3 if solver == "z3" else _solve_cvc5
    results = []
    all_ok = True
    for name in files:
        verdict = solve(os.path.join(smt_dir, name))
        ok = verdict == "unsat"          # ONLY unsat certifies; everything else fails closed
        all_ok = all_ok and ok
        results.append({"file": name, "verdict": verdict, "ok": ok})
    return {"ok": all_ok, "solver": solver, "bundle_sha256": actual_sha, "results": results}
