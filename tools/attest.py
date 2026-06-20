#!/usr/bin/env python3
"""xahau-attest — turn a Hook into a SIGNED, independently-re-checkable certification deliverable.

The VaaS product packaging: one command runs the full invariant battery over a Hook, signs the
PROVEN results into the tamper-evident registry (bound to the on-chain HookHash), and renders a clean
customer deliverable — a machine cert (JSON) + a human scorecard (Markdown). HONEST by construction:
states each invariant's verdict + scope/residual, never an unqualified "safe", and tells the customer
how to re-verify everything themselves (trust the math, not the attester).

Usage:
  python tools/attest.py <hook.wasm | hook.c> --key <attester.key> [--out <dir>] [--customer "Name"]
    --key   : Ed25519 attester key (registry keygen). Required for a SIGNED cert; without it the cert
              is UNSIGNED-but-tamper-evident (registry hash-chain) and says so.
    --out   : output dir (default ./attestations/<hookhash12>-<date>/).

Exit: 0 = no counterexample (all invariants PROVEN or N/A or INCONCLUSIVE) · 2 = a COUNTEREXAMPLE
(the Hook FAILS an invariant — a real defect, the cert reports it) · 3 = setup error.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

XAHC = os.environ.get("XAHC", os.path.expanduser("~/Desktop/xahc/target/release/xahc"))
REPORT = os.path.expanduser("~/dev/xahau-hook-report/report.py")
PY = sys.executable

from watch.manifest import hook_hash_of, wasm_sha256_of  # noqa: E402

VERDICT = {0: ("PROVEN", "holds for ALL inputs (within the invariant's stated scope)"),
           1: ("N/A", "not exercised by this Hook (the property does not apply here)"),
           2: ("COUNTEREXAMPLE", "the Hook VIOLATES this property — a concrete failing input exists"),
           3: ("INCONCLUSIVE", "could not be decided; fail-closed, NOT a pass")}


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def build_if_c(path):
    if path.endswith(".wasm"):
        return path, []
    out = path[:-2] + ".wasm" if path.endswith(".c") else path + ".wasm"
    cc = os.environ.get("CC", "/opt/homebrew/opt/llvm/bin/clang")
    r = sh([XAHC, "build", path, "-o", out], env=dict(os.environ, CC=cc,
            PATH="/opt/homebrew/opt/llvm/bin:" + os.environ.get("PATH", "")))
    if r.returncode != 0 or not os.path.exists(out):
        print(f"BUILD ERROR: {r.stderr[-300:] or r.stdout[-300:]}", file=sys.stderr); sys.exit(3)
    return out, [f"built from {os.path.basename(path)}"]


def run_battery(wasm):
    r = sh([PY, REPORT, wasm, "--json"])
    try:
        return json.loads(r.stdout)
    except Exception:
        print(f"BATTERY ERROR: {r.stderr[-400:] or r.stdout[-400:]}", file=sys.stderr); sys.exit(3)


def sign_proven(wasm, proven_invariants, keyfile, store):
    """Mint + (optionally) sign a registry manifest per PROVEN invariant. Returns (head, signed?)."""
    signed = bool(keyfile)
    for inv in proven_invariants:
        mpath = os.path.join(os.path.dirname(store), f"m_{inv}.json")
        mk = sh([PY, "-m", "registry", "make-manifest", wasm, "--invariant", inv, "--out", mpath],
                env=dict(os.environ, PYTHONPATH=SRC))
        if mk.returncode != 0:
            continue  # fail-closed: a non-PROVEN can't mint; skip silently (it isn't in the proven set anyway)
        add = [PY, "-m", "registry", "--store", store, "add", mpath]
        if keyfile:
            add += ["--key", keyfile]
        sh(add, env=dict(os.environ, PYTHONPATH=SRC))
    head = sh([PY, "-m", "registry", "--store", store, "head"], env=dict(os.environ, PYTHONPATH=SRC)).stdout.strip()
    return head, signed


def attester_pubkey(keyfile):
    if not keyfile:
        return None
    try:
        from registry.signing import load_signer
        s = load_signer(keyfile)
        return s.public_hex() if s else None
    except Exception:
        return None


def render(cert, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "certification.json")
    with open(json_path, "w") as f:
        json.dump(cert, f, indent=2)

    L = []
    L.append(f"# Xahau Hook Certification — {cert['hook']['name']}")
    L.append("")
    L.append(f"**Date:** {cert['date']}  ·  **Attester:** "
             f"{(cert['attester']['pubkey'] or 'UNSIGNED (tamper-evident via registry hash-chain)')}")
    L.append("")
    L.append("## Identity (what this certifies)")
    L.append(f"- **HookHash (on-chain, SHA-512Half):** `{cert['hook']['hook_hash']}`")
    L.append(f"- **WASM SHA-256:** `{cert['hook']['wasm_sha256']}`")
    if cert['hook'].get('notes'):
        L.append(f"- {', '.join(cert['hook']['notes'])}")
    L.append("- The certification applies to **this exact bytecode**. Modify the Hook and its hash "
             "changes — the cert no longer applies (re-certify required).")
    L.append("")
    claimed = cert.get("claimed_invariants")
    if claimed:
        verdict = cert["certification_verdict"]
        badge = "✅ CERTIFIED" if verdict == "CERTIFIED" else "❌ NOT CERTIFIED"
        L.append(f"## Certification verdict: {badge}")
        L.append(f"Certified for the claimed property set: {', '.join('`'+c+'`' for c in claimed)}.")
        if verdict != "CERTIFIED":
            L.append("One or more CLAIMED properties did not prove (COUNTEREXAMPLE or INCONCLUSIVE) — "
                     "see the table; this Hook is NOT certified for its claimed set as-is.")
        L.append("")
        L.append("### Claimed properties (what this Hook is certified for)")
        L.append("| Invariant | Verdict | Meaning |")
        L.append("|---|---|---|")
        for r in [x for x in cert['results'] if x['claimed']]:
            v, _ = VERDICT.get(r['exit'], (f"EXIT_{r['exit']}", ""))
            L.append(f"| `{r['invariant']}` | **{v}** | {r['description']} |")
        L.append("")
        other = [x for x in cert['results'] if not x['claimed'] and x['exit'] != 1]
        if other:
            L.append("### Additional battery results (informational — NOT claimed by this Hook)")
            L.append("A non-match here is not a defect: the Hook does not claim these properties.")
            L.append("| Invariant | Verdict | Meaning |")
            L.append("|---|---|---|")
            for r in other:
                v, _ = VERDICT.get(r['exit'], (f"EXIT_{r['exit']}", ""))
                L.append(f"| `{r['invariant']}` | {v} | {r['description']} |")
            L.append("")
    else:
        L.append("## Full-battery sweep (NOT a scoped certification)")
        L.append(f"- **{cert['summary']['proven']} PROVEN** · {cert['summary']['counterexamples']} "
                 f"COUNTEREXAMPLE · {cert['summary']['inconclusive']} INCONCLUSIVE · "
                 f"{cert['summary']['na']} N/A  (of {cert['summary']['total']} invariants)")
        L.append("> This ran EVERY invariant. A **COUNTEREXAMPLE** on a property the Hook does not "
                 "claim is NOT necessarily a defect — the Hook may not be designed for it. For a real "
                 "certification, re-run with `--invariants <the claimed set>`.")
        L.append("")
        L.append("| Invariant | Verdict | Meaning |")
        L.append("|---|---|---|")
        for r in cert['results']:
            v, _ = VERDICT.get(r['exit'], (f"EXIT_{r['exit']}", ""))
            L.append(f"| `{r['invariant']}` | **{v}** | {r['description']} |")
        L.append("")
    L.append("## What the verdicts mean (honest scope)")
    L.append("- **PROVEN** = holds for *every possible input*, under that invariant's stated scope — "
             "NOT an unqualified \"safe\". Safety is relative to the specific properties proven.")
    L.append("- **N/A** = the property isn't exercised by this Hook (not a failure).")
    L.append("- **INCONCLUSIVE** = the engine couldn't decide it soundly → fail-closed, reported as "
             "NOT proven (never silently passed).")
    L.append("- Proofs are bounded (guarded loop unrolling) and assume SHA-512Half/-256 are sound.")
    L.append("")
    L.append("## Re-verify it yourself (don't trust the attester)")
    L.append("Every PROVEN result is bound to the HookHash in a tamper-evident registry. Re-check via:")
    L.append("- `xahc registry reverify <hook.wasm>` — re-run the open, MIT, deterministic prover.")
    L.append("- `xahc registry recheck <obligations>` — re-solve the SMT obligations with your own solver.")
    L.append("- `xahc registry checkproof <obligations>` — verify the solver-free DRAT proof (engine "
             "AND solver out of the loop).")
    L.append(f"- Registry head (anchorable on-ledger): `{cert['registry_head']}`")
    L.append("")
    L.append("Toolchain: github.com/Hugegreencandle/xahc-prover (MIT). Trust the math, not the attester.")
    md_path = os.path.join(out_dir, "CERTIFICATION.md")
    with open(md_path, "w") as f:
        f.write("\n".join(L) + "\n")
    return json_path, md_path


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__); return 0
    target = sys.argv[1]
    keyfile = sys.argv[sys.argv.index("--key") + 1] if "--key" in sys.argv else None
    customer = sys.argv[sys.argv.index("--customer") + 1] if "--customer" in sys.argv else None
    # --invariants a,b,c = the CLAIMED property set this Hook is certified FOR. A COUNTEREXAMPLE in the
    # claimed set is a real CERTIFICATION FAILURE. Other battery results are informational only (a
    # non-match on an UNCLAIMED property is NOT a defect — the Hook may not be designed for it).
    claimed = ([s.strip() for s in sys.argv[sys.argv.index("--invariants") + 1].split(",") if s.strip()]
               if "--invariants" in sys.argv else None)

    wasm, notes = build_if_c(target)
    with open(wasm, "rb") as f:
        b = f.read()
    hh = hook_hash_of(b)
    date = sh(["date", "+%F"]).stdout.strip()
    out_dir = (sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv
               else os.path.join(os.getcwd(), "attestations", f"{hh[:12]}-{date}"))

    batt = run_battery(wasm)
    rows = batt["results"]
    # attach the plain-English description per invariant from report.py's BATTERY
    sys.path.insert(0, os.path.dirname(REPORT))
    try:
        from report import BATTERY  # noqa
        desc = dict(BATTERY)
    except Exception:
        desc = {}
    for r in rows:
        r["description"] = desc.get(r["invariant"], "")

    for r in rows:
        r["claimed"] = (claimed is None) or (r["invariant"] in claimed)
    proven = [r["invariant"] for r in rows if r["exit"] == 0]
    n_cex = sum(1 for r in rows if r["exit"] == 2)
    n_inc = sum(1 for r in rows if r["exit"] == 3)
    n_na = sum(1 for r in rows if r["exit"] == 1)
    # The certification verdict is over the CLAIMED set only (or the whole battery if no claim given).
    claimed_rows = [r for r in rows if r["claimed"]]
    claimed_cex = [r for r in claimed_rows if r["exit"] == 2]
    claimed_inc = [r for r in claimed_rows if r["exit"] == 3]
    cert_passes = (not claimed_cex) and (not claimed_inc) and bool(claimed_rows)

    os.makedirs(out_dir, exist_ok=True)
    store = os.path.join(out_dir, "registry.jsonl")
    head, signed = sign_proven(wasm, proven, keyfile, store)
    pub = attester_pubkey(keyfile)

    cert = {
        "kind": "xahau-hook-certification", "version": 1, "date": date,
        "customer": customer,
        "claimed_invariants": claimed,           # None = full-battery sweep (not a scoped certification)
        "certification_verdict": ("CERTIFIED" if cert_passes else "NOT CERTIFIED") if claimed else "SWEEP",
        "hook": {"name": os.path.basename(wasm), "hook_hash": hh,
                 "wasm_sha256": wasm_sha256_of(b), "notes": notes},
        "attester": {"pubkey": pub, "signed": bool(pub)},
        "results": rows,
        "summary": {"proven": len(proven), "counterexamples": n_cex,
                    "inconclusive": n_inc, "na": n_na, "total": len(rows),
                    "claimed_total": len(claimed_rows), "claimed_cex": len(claimed_cex)},
        "registry_head": head,
        "recheck": ["reverify", "recheck", "checkproof"],
    }
    jp, mp = render(cert, out_dir)

    verdict = cert["certification_verdict"]
    print(f"hook {hh[:16]}… | {verdict} | PROVEN {len(proven)} · CEX {n_cex} · INCONCLUSIVE {n_inc} · "
          f"N/A {n_na} | {'SIGNED' if pub else 'UNSIGNED (tamper-evident)'}")
    print(f"certification -> {mp}")
    print(f"            json -> {jp}")
    if claimed and not cert_passes:
        print(f"\n⚠️ NOT CERTIFIED — a CLAIMED invariant failed: "
              f"CEX {[r['invariant'] for r in claimed_cex]} INCONCLUSIVE {[r['invariant'] for r in claimed_inc]}")
        return 2
    if claimed is None and n_cex:
        print("\n(full-battery sweep — a COUNTEREXAMPLE on a property the Hook doesn't claim is NOT a "
              "defect. Use --invariants to certify a claimed set.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
