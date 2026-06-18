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
from registry.signing import Signer, load_signer, crypto_available
from watch.manifest import load_manifest


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

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
