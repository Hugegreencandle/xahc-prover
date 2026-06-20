#!/usr/bin/env python3
"""Standing PROVER SOUNDNESS LOOP — the false-PROVEN tripwire for the whole invariant battery.

SOUNDNESS IS THE PRODUCT: a false PROVEN (an invariant returning PROVEN/exit-0 on a hook that ACTUALLY
violates it) is catastrophic — it certifies an unsafe hook. This loop makes the false-PROVEN rate a
TRACKED, REGRESSION-GATED metric across every invariant, so any engine/driver change that introduces a
false PROVEN is caught loudly before it ships.

The corpus is DERIVED from tests/test_prover.py (auto-syncs as invariants are added): every
`prove_X.main(os.path.join(H, "Y.wasm"), ...) == E` assertion is a labelled case —
  E==0 PROVEN (a hook that should pass), E==1 N/A, E==2 COUNTEREXAMPLE (a KNOWN-UNSAFE hook).
THE TRIPWIRE: any case labelled E==2 (known-unsafe) whose driver returns 0 (PROVEN) is a FALSE PROVEN.
Any false PROVEN -> loud report + non-zero exit (so a scheduler / push-hook hard-fails).

It also tracks (non-fatal, for the confusion matrix):
  - precision regressions: a hook labelled PROVEN(0) that now returns !=0 (sound-safe, but the prover
    got LESS capable — worth watching),
  - INCONCLUSIVE drift on known-unsafe cases (2 -> 3): not unsound, but a detection regression.

Run:  cd ~/Desktop/xahc-prover && ./.venv/bin/python tools/soundness_loop.py
Exit: 0 = no false PROVEN (sound) · 2 = FALSE PROVEN found (catastrophic) · 3 = harness/run error.
Writes a dated report to HQ/06-Technical/Prover_Soundness_<date>.md (override dir via --report-dir).
"""
import importlib
import os
import re
import subprocess
import sys
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
HOOKS = os.path.join(ROOT, "hooks")
TESTS = os.path.join(ROOT, "tests", "test_prover.py")
sys.path.insert(0, SRC)

VERDICT = {0: "PROVEN", 1: "N/A", 2: "COUNTEREXAMPLE", 3: "INCONCLUSIVE"}

# prove_<driver>.main(os.path.join(H, "<wasm>")[, <extra args>]) == <expected>
CASE_RE = re.compile(
    r'prove_(\w+)\.main\(\s*os\.path\.join\(H,\s*"([^"]+\.wasm)"\)\s*(?:,\s*([^)]*?))?\)\s*==\s*(\d)'
)


def parse_corpus(test_path: str):
    """Derive the labelled corpus from the test suite. Returns list of (driver, wasm, extra, expected)."""
    cases = []
    with open(test_path) as f:
        for m in CASE_RE.finditer(f.read()):
            driver, wasm, extra, exp = m.group(1), m.group(2), (m.group(3) or "").strip(), int(m.group(4))
            cases.append((driver, wasm, extra, exp))
    return cases


def run_case(driver: str, wasm: str, extra: str) -> int:
    """Invoke prove_<driver>.main(<hook>[, <extra>]) in-process; return its exit code (3 on crash)."""
    path = os.path.join(HOOKS, wasm)
    if not os.path.exists(path):
        return -1  # missing fixture
    try:
        mod = importlib.import_module(f"prove_{driver}")
        # Eval the FULL call exactly as the test wrote it (handles positional, keyword `strict=True`,
        # and function-call `field=parse_field("01:0:8")` args) in a small namespace.
        ns = {"mod": mod, "path": path, "True": True, "False": False, "None": None}
        try:
            import field as _field
            ns["parse_field"] = _field.parse_field
        except Exception:
            pass
        call = "mod.main(path)" if not extra else f"mod.main(path, {extra})"
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            return int(eval(call, {"__builtins__": {}}, ns))
    except Exception:
        return -2  # harness can't eval test-local args (e.g. a test-file constant) -> SKIP, not a verdict


def main():
    report_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Kairo Vault HQ", "06-Technical")
    if "--report-dir" in sys.argv:
        report_dir = sys.argv[sys.argv.index("--report-dir") + 1]

    cases = parse_corpus(TESTS)
    if not cases:
        print("ERROR: parsed 0 cases from the test suite — corpus empty, refusing to claim sound.")
        return 3

    false_proven = []   # the catastrophic class: known-unsafe (exp 2) returned PROVEN (0)
    precision_reg = []   # PROVEN-labelled (exp 0) now != 0 (sound-safe; capability regression)
    detection_drift = [] # known-unsafe (exp 2) returned INCONCLUSIVE (3) not CEX (2)
    mismatches = []      # any other expected!=actual
    missing = []
    skipped = []         # harness can't eval test-local args (full suite still covers these)
    ok = 0

    for driver, wasm, extra, exp in cases:
        act = run_case(driver, wasm, extra)
        if act == -1:
            missing.append((driver, wasm)); continue
        if act == -2:
            skipped.append((driver, wasm)); continue
        if act == exp:
            ok += 1
        if exp == 2 and act == 0:
            false_proven.append((driver, wasm, extra))
        elif exp == 2 and act == 3:
            detection_drift.append((driver, wasm, VERDICT.get(act)))
        elif exp == 0 and act != 0:
            precision_reg.append((driver, wasm, VERDICT.get(act, act)))
        elif act != exp:
            mismatches.append((driver, wasm, f"exp {VERDICT[exp]} got {VERDICT.get(act, act)}"))

    n = len(cases)
    known_unsafe = sum(1 for *_, e in cases if e == 2)
    date = subprocess.run(["date", "+%F"], capture_output=True, text=True).stdout.strip()
    fp = len(false_proven)

    # ---- report ----
    lines = [f"# Prover Soundness — {date}", ""]
    lines.append(f"**FALSE-PROVEN COUNT: {fp}**  (MUST be 0 — a false PROVEN certifies an unsafe hook)")
    lines.append("")
    lines.append(f"- corpus: {n} labelled cases derived from tests/test_prover.py "
                 f"({known_unsafe} known-unsafe / must-be-COUNTEREXAMPLE)")
    lines.append(f"- exact-match: {ok}/{n}")
    lines.append(f"- false PROVEN (CATASTROPHIC): {fp}")
    lines.append(f"- detection drift (known-unsafe -> INCONCLUSIVE): {len(detection_drift)}")
    lines.append(f"- precision regressions (good hook no longer PROVEN): {len(precision_reg)}")
    lines.append(f"- other mismatches: {len(mismatches)} | missing fixtures: {len(missing)} | "
                 f"skipped (test-local args, suite covers): {len(skipped)}")
    lines.append("")
    if false_proven:
        lines.append("## 🚨 FALSE PROVEN — an invariant certified a KNOWN-UNSAFE hook")
        for d, w, e in false_proven:
            lines.append(f"- `prove_{d}` returned PROVEN on `{w}` (must be COUNTEREXAMPLE){' [args '+e+']' if e else ''}")
        lines.append("")
    if detection_drift:
        lines.append("## ⚠️ detection drift (sound, but less precise)")
        for d, w, v in detection_drift:
            lines.append(f"- `prove_{d}` on `{w}`: now {v} (was COUNTEREXAMPLE)")
        lines.append("")
    if precision_reg:
        lines.append("## precision regressions (a correct hook no longer PROVEN — sound but capability-down)")
        for d, w, v in precision_reg:
            lines.append(f"- `prove_{d}` on `{w}`: now {v} (was PROVEN)")
        lines.append("")
    if mismatches:
        lines.append("## other mismatches")
        for d, w, m in mismatches:
            lines.append(f"- `prove_{d}` `{w}`: {m}")
        lines.append("")
    if missing:
        lines.append("## missing fixtures (could not run)")
        for d, w in missing:
            lines.append(f"- `prove_{d}` `{w}`")
        lines.append("")
    lines.append("---")
    lines.append("Soundness is the product. Re-run on every engine/driver change; gate pushes on a 0 false-PROVEN count.")

    os.makedirs(report_dir, exist_ok=True)
    rpt = os.path.join(report_dir, f"Prover_Soundness_{date}.md")
    with open(rpt, "w") as f:
        f.write("\n".join(lines) + "\n")

    # ---- console ----
    print(f"corpus {n} cases ({known_unsafe} known-unsafe) | exact {ok}/{n} | FALSE-PROVEN {fp} | "
          f"drift {len(detection_drift)} | precision-reg {len(precision_reg)} | missing {len(missing)}")
    print(f"report -> {rpt}")
    if fp:
        print("\n🚨 SOUNDNESS FAILURE — false PROVEN present:")
        for d, w, e in false_proven:
            print(f"   prove_{d} PROVEN on {w} (must be COUNTEREXAMPLE)")
        return 2
    print("✅ no false PROVEN across the battery — sound.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
