"""`python -m registry <command>` — the Proof Registry CLI.

Commands:
  add <manifest.json> [--store P] [--key K] [--at TS]   register a PROVEN manifest
  get <HookHash>            [--store P] [--json]         status for a HookHash
  check <hook.wasm>         [--store P] [--json]         resolve wasm -> HookHash -> status
  verify                    [--store P] [--json]         re-check the whole chain + signatures
  list                      [--store P] [--json]         per-hook rollup + head + integrity
  head                      [--store P]                  print the head commitment (on-chain anchor)
  keygen                    [--out keyfile]              generate an Ed25519 attester key

Exit codes: 0 ok / PROVEN · 2 UNPROVEN or chain-broken/TAMPERED · 3 usage/error.
"""
from __future__ import annotations

import argparse
import json
import sys

from registry import registry as R
from registry.recheck import recheck_dir
from registry.signing import Signer, load_signer, crypto_available
from smt_export import bundle_sha256
from proof_object import proof_bundle_sha256, ProofObjectError, ToolMissing
from watch.manifest import load_manifest, build_manifest, write_manifest


def _emit(obj: dict, as_json: bool, human) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, sort_keys=True))
    else:
        human(obj)


def cmd_add(a) -> int:
    m = load_manifest(a.manifest)
    signer = load_signer(a.key)
    try:
        e = R.add(m, a.store, signer=signer, recorded_at=a.at)
    except ValueError as ex:
        print(f"refused: {ex}", file=sys.stderr)
        return 2
    mode = "signed" if e.signed else ("unsigned" if not crypto_available() else "unsigned (no key)")
    print(f"registered #{e.index}  {e.invariant}  hook {e.hook_hash[:12]}…  [{mode}]")
    print(f"head: {e.entry_hash}")
    return 0


def cmd_get(a) -> int:
    out = R.status_of(a.hook_hash, a.store, a.pin)
    _emit(out, a.json, _print_status)
    return 0 if out["status"] == R.PROVEN else 2


def cmd_check(a) -> int:
    out = R.status_of_wasm(a.wasm, a.store, a.pin)
    _emit(out, a.json, _print_status)
    return 0 if out["status"] == R.PROVEN else 2


def cmd_verify(a) -> int:
    ok, reason = R.verify_chain(a.store, a.pin)
    out = {"chain_ok": ok, "chain_break": reason, "head": R.head(a.store)}
    _emit(out, a.json, lambda o: print(
        f"chain OK — head {o['head'][:16]}…" if o["chain_ok"]
        else f"CHAIN BROKEN: {o['chain_break']}"))
    return 0 if ok else 2


def cmd_list(a) -> int:
    out = R.summary(a.store)
    _emit(out, a.json, _print_summary)
    return 0 if out["chain_ok"] else 2


def cmd_head(a) -> int:
    print(R.head(a.store))
    return 0


def cmd_make_manifest(a) -> int:
    """Build a ProofManifest JSON from a proven .wasm (fail-closed: non-PROVEN can't be written).

    The prove→manifest→register seam: `xahc author`/CI proves an invariant, then mints the
    manifest here. exit_code defaults to 0 (PROVEN); a non-zero value is REFUSED by write_manifest.
    """
    with open(a.wasm, "rb") as f:
        wasm = f.read()
    verdict = a.verdict or ("PROVEN" if a.exit == 0 else "NOT-PROVEN")
    smt_sha = bundle_sha256(a.smt) if a.smt else None
    po_sha = None
    if a.proof_object:
        import tempfile
        try:
            po_sha = proof_bundle_sha256(a.proof_object, tempfile.mkdtemp())
        except (ProofObjectError, ToolMissing) as ex:
            # fail-closed: never record a proof-object hash unless every DRAT proof verified
            print(f"refused: proof-object binding failed: {ex}", file=sys.stderr)
            return 2
    m = build_manifest(wasm=wasm, invariant=a.invariant, verdict=verdict, exit_code=a.exit,
                       scope_caveats=a.caveat or [], hook_account=a.account, network_id=a.network,
                       prover_args=a.prover_arg or [], smt_sha256=smt_sha, proof_object_sha256=po_sha)
    try:
        write_manifest(m, a.out)
    except ValueError as ex:
        print(f"refused: {ex}", file=sys.stderr)
        return 2
    print(f"wrote manifest -> {a.out}  ({a.invariant}, hook {m.hook_hash[:12]}…)")
    return 0


def cmd_keygen(a) -> int:
    if not crypto_available():
        print("cannot keygen: `cryptography` is not installed (registry still works unsigned)",
              file=sys.stderr)
        return 3
    s = Signer.generate()
    seed, pub = s.seed_hex(), s.public_hex()
    if a.out:
        with open(a.out, "w") as f:
            f.write(seed + "\n")
        print(f"wrote attester key -> {a.out}")
        print(f"public key: {pub}")
        print("keep the keyfile secret; share/pin the public key.")
    else:
        print(f"seed (secret): {seed}")
        print(f"public key:    {pub}")
    return 0


def cmd_checkproof(a) -> int:
    """Solver-free re-check (verify-the-proof, strongest rung): for each obligation, bit-blast ->
    cadical DRAT -> drat-trim VERIFIED, with the SMT engine AND solver out of the trust loop. Records
    nothing; just re-derives the proof-object bundle hash and (optionally) matches it to the manifest."""
    import tempfile
    try:
        sha = proof_bundle_sha256(a.smt_dir, tempfile.mkdtemp())
    except (ProofObjectError, ToolMissing) as ex:
        o = {"ok": False, "reason": str(ex)}
        _emit(o, a.json, lambda x: print(f"\n✗ checkproof FAILED — {x['reason']}"))
        return 2
    ok = (a.expect_sha256 is None) or (sha == a.expect_sha256)
    o = {"ok": ok, "proof_object_sha256": sha, "expected": a.expect_sha256}

    def _p(x):
        if not x["ok"]:
            print(f"\n✗ checkproof — bundle {x['proof_object_sha256'][:16]}… ≠ manifest "
                  f"{(x['expected'] or '')[:16]}…; the proof artifacts don't match what was attested.")
        else:
            print(f"\n✓ checkproof — every obligation's DRAT proof re-derived + VERIFIED by drat-trim "
                  f"(cadical-solved, SMT engine NOT run). bundle {x['proof_object_sha256'][:16]}…")
    _emit(o, a.json, _p)
    return 0 if ok else 2


def cmd_recheck(a) -> int:
    """Re-solve the exported SMT obligations with an independent solver (verify-the-proof v2)."""
    res = recheck_dir(a.smt_dir, solver=a.solver, expect_sha256=a.expect_sha256)
    _emit(res, a.json, _print_recheck)
    return 0 if res.get("ok") else 2


def _print_recheck(o: dict) -> None:
    if not o.get("results"):
        print(f"✗ RECHECK FAILED: {o.get('reason', 'no obligations')}")
        return
    for r in o["results"]:
        print(f"  {'✓' if r['ok'] else '✗'} {r['file']}  -> {r['verdict']}")
    if o.get("ok"):
        print(f"\n✓ all {len(o['results'])} obligation(s) re-solved UNSAT with {o['solver']} "
              f"— independently re-checked; the xahc engine was NOT run.")
    else:
        print(f"\n✗ recheck FAILED — not every obligation re-solved unsat. {o.get('reason', '')}")


def _print_status(o: dict) -> None:
    s = o["status"]
    mark = {"PROVEN": "✓", "UNPROVEN": "○", "TAMPERED": "✗"}.get(s, "?")
    print(f"{mark} {s}  {o.get('hook_hash', '')[:16]}…")
    if s == R.PROVEN:
        sg = "signed" if o.get("signed") else "unsigned"
        print(f"  invariants: {', '.join(o['invariants'])}  [{sg}]")
        if o.get("residual"):
            print(f"  residual:   {'; '.join(o['residual'])}")
        if o.get("hook_accounts"):
            print(f"  accounts:   {', '.join(o['hook_accounts'])}")
    else:
        print(f"  {o.get('detail', '')}")


def _print_summary(o: dict) -> None:
    print(f"Proof Registry — {len(o['hooks'])} hook(s)   "
          f"chain {'OK' if o['chain_ok'] else 'BROKEN'}   head {o['head'][:16]}…")
    if not o["chain_ok"]:
        print(f"  ✗ CHAIN BROKEN: {o['chain_break']}")
    for h in o["hooks"]:
        sg = "signed" if h["signed"] else "unsigned"
        print(f"  {h['hook_hash'][:16]}…  [{sg}]  {', '.join(h['invariants'])}")
        if h["residual"]:
            print(f"       residual: {'; '.join(h['residual'])}")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="registry", description="Xahau Hook Proof Registry")
    p.add_argument("--store", default=R.DEFAULT_STORE, help="registry log path")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("add"); pa.add_argument("manifest"); pa.add_argument("--key")
    pa.add_argument("--at", help="recorded_at timestamp (caller-supplied)"); pa.set_defaults(fn=cmd_add)
    pg = sub.add_parser("get"); pg.add_argument("hook_hash"); pg.add_argument("--json", action="store_true"); pg.add_argument("--pin", help="require the chain be signed by this attester pubkey (hex)"); pg.set_defaults(fn=cmd_get)
    pc = sub.add_parser("check"); pc.add_argument("wasm"); pc.add_argument("--json", action="store_true"); pc.add_argument("--pin", help="require the chain be signed by this attester pubkey (hex)"); pc.set_defaults(fn=cmd_check)
    pv = sub.add_parser("verify"); pv.add_argument("--json", action="store_true"); pv.add_argument("--pin", help="require the chain be signed by this attester pubkey (hex)"); pv.set_defaults(fn=cmd_verify)
    pl = sub.add_parser("list"); pl.add_argument("--json", action="store_true"); pl.set_defaults(fn=cmd_list)
    ph = sub.add_parser("head"); ph.set_defaults(fn=cmd_head)
    pk = sub.add_parser("keygen"); pk.add_argument("--out"); pk.set_defaults(fn=cmd_keygen)
    pm = sub.add_parser("make-manifest"); pm.add_argument("wasm"); pm.add_argument("--invariant", required=True)
    pm.add_argument("--exit", type=int, default=0, dest="exit"); pm.add_argument("--verdict")
    pm.add_argument("--account"); pm.add_argument("--network", type=int)
    pm.add_argument("--caveat", action="append")
    pm.add_argument("--prover-arg", action="append", dest="prover_arg",
                    help="exact prover driver arg to record for replay (repeatable), e.g. --field 01:0:8")
    pm.add_argument("--smt", help="dir of exported .smt2 obligations; records its bundle sha256 for recheck")
    pm.add_argument("--proof-object", dest="proof_object",
                    help="dir of exported .smt2; produce+verify solver-free DRAT proof objects (fail-closed) + record their bundle sha256 for checkproof")
    pm.add_argument("--out", required=True)
    pm.set_defaults(fn=cmd_make_manifest)
    prc = sub.add_parser("recheck"); prc.add_argument("smt_dir")
    prc.add_argument("--solver", default="z3", choices=["z3", "cvc5"])
    prc.add_argument("--expect-sha256", dest="expect_sha256",
                     help="require the bundle to match this sha256 (bind to a registered artifact)")
    prc.add_argument("--json", action="store_true"); prc.set_defaults(fn=cmd_recheck)

    pcp = sub.add_parser("checkproof"); pcp.add_argument("smt_dir")
    pcp.add_argument("--expect-sha256", dest="expect_sha256",
                     help="require the re-derived proof-object bundle to match this manifest hash")
    pcp.add_argument("--json", action="store_true"); pcp.set_defaults(fn=cmd_checkproof)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
