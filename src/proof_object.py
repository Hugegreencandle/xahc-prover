"""Solver-free proof objects — the verify-the-proof endgame for QF_BV obligations.

`recheck` re-solves an obligation's SMT with any solver (trust a SOLVER). This goes one rung
further: turn the obligation into a SAT proof a SMALL CHECKER validates, trusting NO solver.

Pipeline (per emitted .smt2 obligation, which must be UNSAT):
    .smt2 (QF_BV)  --z3 bit-blast-->  DIMACS CNF  --cadical-->  DRAT proof  --drat-trim-->  VERIFIED

The checker (drat-trim) re-derives the empty clause from the proof without running the SMT engine or
trusting the SAT solver's word. Trust base shrinks to: (a) the bit-blast/CNF encoding (z3 tactic),
(b) the proof checker. Honest residual: the encoding faithfulness is still trusted; swapping
drat-trim for cake_lpr (CakeML-formally-verified, LRAT) removes the checker from the trusted base.

External tools (resolved on PATH or via XAHC_CADICAL / XAHC_DRAT_TRIM):
  - cadical (SAT solver that emits canonical DRAT)
  - drat-trim (DRAT checker)
FAIL-CLOSED: a missing tool / non-UNSAT / unverified proof raises — never a silent pass.
"""
import os
import shutil
import subprocess
import hashlib

import z3


CHECK_TIMEOUT_S = 120   # per-obligation cadical/drat-trim wall-clock cap; a hang -> fail closed


class ToolMissing(RuntimeError):
    pass


class ProofObjectError(RuntimeError):
    pass


def _tool(name: str, env_var: str) -> str:
    path = os.environ.get(env_var) or shutil.which(name)
    if not path:
        raise ToolMissing(f"{name} not found (set {env_var} or put it on PATH)")
    return path


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalize_dimacs(dimacs: str) -> str:
    """z3's Goal.dimacs() can emit a `p cnf V C` header whose V under-counts the variables
    actually used (a literal can exceed the declared max), which cadical rejects. The clause
    bodies are correct — so recompute the header from the real literals. Sound: widening the
    declared variable count never changes satisfiability."""
    clauses, maxvar = [], 0
    for line in dimacs.splitlines():
        s = line.strip()
        if not s or s[0] in ("c", "p"):
            continue
        clauses.append(s)
        for tok in s.split():
            if tok not in ("0", ""):
                v = abs(int(tok))
                if v > maxvar:
                    maxvar = v
    return f"p cnf {maxvar} {len(clauses)}\n" + "\n".join(clauses) + "\n"


def bitblast_to_cnf(smt2_path: str, cnf_path: str) -> None:
    """QF_BV .smt2 -> DIMACS CNF via z3's bit-blast tactic (header normalized)."""
    g = z3.Goal()
    g.add(z3.parse_smt2_file(smt2_path))
    sub = z3.Then("simplify", "bit-blast", "tseitin-cnf")(g)[0]
    with open(cnf_path, "w") as f:
        f.write(_normalize_dimacs(sub.dimacs()))


def make_and_verify(smt2_path: str, work_dir: str) -> dict:
    """Produce a DRAT proof object for one obligation and independently verify it.

    Returns {verified, cnf_sha256, drat_sha256, cnf, drat}. Raises ProofObjectError if the
    obligation is not UNSAT, or if drat-trim does not report VERIFIED (fail-closed)."""
    cadical = _tool("cadical", "XAHC_CADICAL")
    drat_trim = _tool("drat-trim", "XAHC_DRAT_TRIM")
    os.makedirs(work_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(smt2_path))[0]
    cnf = os.path.join(work_dir, base + ".cnf")
    drat = os.path.join(work_dir, base + ".drat")

    bitblast_to_cnf(smt2_path, cnf)

    # cadical exits 20 for UNSAT, 10 for SAT. A SAT obligation = the proof DOESN'T hold -> fail closed.
    # FAIL-CLOSED on hang: a stuck checker must raise, never block proof minting indefinitely.
    try:
        r = subprocess.run([cadical, cnf, drat], capture_output=True, text=True, timeout=CHECK_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise ProofObjectError(f"{base}: cadical timed out after {CHECK_TIMEOUT_S}s (fail closed)")
    if r.returncode == 10:
        raise ProofObjectError(f"{base}: obligation is SATISFIABLE — the property does NOT hold "
                               "(this is a counterexample, not a proof)")
    if r.returncode != 20:
        raise ProofObjectError(f"{base}: cadical did not return UNSAT (rc={r.returncode}) "
                               f"{(r.stderr or r.stdout or '')[-200:].strip()}")

    try:
        v = subprocess.run([drat_trim, cnf, drat], capture_output=True, text=True, timeout=CHECK_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise ProofObjectError(f"{base}: drat-trim timed out after {CHECK_TIMEOUT_S}s (fail closed)")
    # parse the verdict line-wise (not a loose substring): drat-trim prints "s VERIFIED" on its own line.
    verified = any(line.strip() == "s VERIFIED" for line in v.stdout.splitlines())
    if not verified:
        raise ProofObjectError(f"{base}: drat-trim did NOT verify the proof\n{v.stdout[-400:]}")

    return {
        "verified": True,
        "cnf_sha256": _sha256(cnf),
        "drat_sha256": _sha256(drat),
        "cnf": cnf,
        "drat": drat,
    }


def verify_dir(obl_dir: str, work_dir: str) -> dict:
    """Make + verify a proof object for every .smt2 in obl_dir. Returns a summary; the per-file
    'verified' is True only if the independent checker confirmed it."""
    results = {}
    for name in sorted(os.listdir(obl_dir)):
        if not name.endswith(".smt2"):
            continue
        path = os.path.join(obl_dir, name)
        try:
            results[name] = make_and_verify(path, work_dir)
        except ProofObjectError as e:
            results[name] = {"verified": False, "error": str(e)}
    n = len(results)
    ok = sum(1 for r in results.values() if r.get("verified"))
    return {"total": n, "verified": ok, "failed": n - ok, "results": results}


def proof_bundle_sha256(smt_dir: str, work_dir: str) -> str:
    """Produce + verify a DRAT proof object for EVERY obligation in smt_dir, then return one bundle
    sha256 over the sorted per-file (cnf,drat) hashes. FAIL-CLOSED: raises if there are no
    obligations, or if ANY proof object fails to verify — a bundle hash exists only when every
    solver-free proof checked. This is what the registry manifest binds (proof_object_sha256)."""
    s = verify_dir(smt_dir, work_dir)
    if s["total"] == 0:
        raise ProofObjectError(f"no .smt2 obligations in {smt_dir}")
    if s["failed"]:
        bad = [n for n, r in s["results"].items() if not r.get("verified")]
        raise ProofObjectError(f"{s['failed']}/{s['total']} proof object(s) did not verify: {bad}")
    # Bind the OBLIGATIONS (the deterministic .smt2 text the engine emitted), NOT the ephemeral DRAT
    # (a SAT solver emits a different valid proof each run) nor z3's CNF (Goal.dimacs() variable
    # numbering isn't stable across calls). The recorded value's MEANING: every obligation was
    # independently solver-free-checked (bit-blast -> cadical -> drat-trim VERIFIED) at mint time;
    # checkproof re-derives a fresh DRAT and re-verifies. This is the same obligation identity recheck
    # uses, so the two methods bind the same claim by different checkers.
    from smt_export import bundle_sha256
    return bundle_sha256(smt_dir)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    wd = sys.argv[2] if len(sys.argv) > 2 else "/tmp/xahc-proof-objects"
    try:
        if os.path.isdir(target):
            s = verify_dir(target, wd)
            for nm, r in s["results"].items():
                mark = "✓ VERIFIED" if r.get("verified") else "✗ " + r.get("error", "FAILED")[:80]
                print(f"  {mark}  {nm}")
            print(f"\nsolver-free proof objects: {s['verified']}/{s['total']} verified "
                  f"(checked by drat-trim — the SMT engine was NOT run)")
            sys.exit(0 if s["failed"] == 0 and s["total"] > 0 else 1)
        else:
            r = make_and_verify(target, wd)
            print(f"✓ VERIFIED  cnf={r['cnf_sha256'][:16]} drat={r['drat_sha256'][:16]}")
            sys.exit(0)
    except (ToolMissing, ProofObjectError) as e:
        print(f"✗ {e}")
        sys.exit(2)
