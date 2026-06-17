"""xahc-watch — bind a proof to a deployed hook and continuously attest it.

Every observed transaction the watched hook executed on lands in EXACTLY ONE bucket:

  CONSISTENT  — the chain's accept/reject matches the proven predicate's expectation. (quiet)
  VIOLATION   — the hook ACCEPTED a tx the proof says it must REJECT. (critical, pages, exit≠0)
  PROOF_VOID  — the deployed HookHash ≠ the proven HookHash: the running code isn't the proven
                code (a SetHook swapped it). The proof no longer applies. (critical, exit≠0)
  UNVERIFIED  — out of the proof's model: an undecodable/IOU amount, a non-clean engine result,
                or the hook was MORE restrictive than the model predicted (rejected for a reason
                the invariant doesn't cover). watch's INCONCLUSIVE — LOUD, never "consistent".

There is no implicit "ok". Silence is never safety. (See CLAUDE.md: SOUNDNESS IS THE PRODUCT.)

The accept/reject expectation comes from the SHARED predicate in watch.predicates — the exact
rule xahc-prover proved — so the watcher cannot drift from the proof.

CLI:
  python -m watch <manifest.json> --replay <fixture.json> [--account r...]   # offline
  python -m watch <manifest.json> --ws wss://host [--account r...]           # live (network)
"""
from __future__ import annotations

import json
import sys
from typing import Optional

from watch.manifest import load_manifest, ProofManifest
from watch.predicates import guardrail_expected, ACCEPT_OK, SHOULD_REJECT, UNVERIFIED as P_UNVERIFIED
from watch import ledger

# buckets
CONSISTENT = "CONSISTENT"
VIOLATION = "VIOLATION"
PROOF_VOID = "PROOF_VOID"
UNVERIFIED = "UNVERIFIED"
SKIP = "SKIP"           # the watched hook did not execute on this tx (not classified/quiet)

CRITICAL = (VIOLATION, PROOF_VOID)


def _params_for_predicate(m: ProofManifest) -> dict:
    """Manifest params -> the concrete predicate's param form (LIM:int, DST:bytes20|None)."""
    p = dict(m.params or {})
    out = {"LIM": p.get("LIM")}
    dst_hex = p.get("DST")
    if dst_hex:
        out["DST"] = bytes.fromhex(dst_hex)
    return out


def classify(record: dict, manifest: ProofManifest, hook_account: Optional[str]) -> tuple[str, str]:
    """Classify one transaction record into a bucket. `hook_account` is the bound r-address
    (manifest.hook_account or --account); used to pick the watched hook's execution + as the
    predicate's hook_account scope. Returns (bucket, human detail)."""
    ex = ledger.watched_execution(record, manifest.hook_hash, hook_account)
    if ex is None:
        return SKIP, "watched hook did not execute on this tx"

    # 1) BINDING — the running code must be the proven code, else the proof does not apply.
    if ex["hook_hash"] != manifest.hook_hash.upper():
        return PROOF_VOID, (f"deployed HookHash {ex['hook_hash'][:8]}… ≠ proven "
                            f"{manifest.hook_hash[:8]}… — running code is not the proven code "
                            "(SetHook swap?); proof no longer applies")

    # 2) ATTESTATION — the chain's decision vs the proven predicate's expectation.
    if hook_account is None:
        return UNVERIFIED, "no bound hook account to scope the predicate"
    hook_acct_id = ledger.account_id(hook_account)
    fields = ledger.tx_fields(record, hook_acct_id)
    predicted = guardrail_expected(fields, _params_for_predicate(manifest))

    res = ledger.engine_result(record)
    if res == "tesSUCCESS":
        observed = "ACCEPT"
    elif res == "tecHOOK_REJECTED":
        observed = "REJECT"
    else:
        observed = "OTHER"

    if predicted == P_UNVERIFIED:
        return UNVERIFIED, f"out of model (predicate UNVERIFIED); engine_result={res}"
    if observed == "OTHER":
        return UNVERIFIED, f"engine_result={res} is not a clean hook accept/reject"
    if predicted == SHOULD_REJECT and observed == "ACCEPT":
        return VIOLATION, ("proof requires REJECT but the hook ACCEPTED this tx "
                           f"(engine_result={res})")
    if predicted == SHOULD_REJECT and observed == "REJECT":
        return CONSISTENT, "proof requires REJECT; chain rejected"
    if predicted == ACCEPT_OK and observed == "ACCEPT":
        return CONSISTENT, "proof allows ACCEPT; chain accepted"
    # predicted ACCEPT_OK but the chain REJECTED — safe (more restrictive) but unexplained by
    # the modeled invariant (guard? another policy?). Loud, not consistent. Never a VIOLATION.
    return UNVERIFIED, ("chain rejected a tx the modeled invariant would allow — restriction "
                        f"outside this invariant (engine_result={res})")


def _emit(bucket: str, detail: str, record: dict) -> None:
    icon = {CONSISTENT: "✅", VIOLATION: "🚨", PROOF_VOID: "🚨", UNVERIFIED: "⚠️", SKIP: "·"}[bucket]
    h = record.get("hash", "?")
    if bucket == SKIP:
        return  # quiet — irrelevant tx
    print(f"{icon} {bucket:<10} {h}  {detail}")


def replay(manifest_path: str, fixture_path: str, account: Optional[str] = None) -> int:
    """Offline: classify every record in a committed fixture. Exit 0 unless any CRITICAL bucket
    (VIOLATION / PROOF_VOID) appeared, or a rising UNVERIFIED count merits attention (reported)."""
    m = load_manifest(manifest_path)
    acct = account or m.hook_account
    with open(fixture_path) as f:
        fixture = json.load(f)
    records = fixture["transactions"] if isinstance(fixture, dict) else fixture

    tally = {CONSISTENT: 0, VIOLATION: 0, PROOF_VOID: 0, UNVERIFIED: 0, SKIP: 0}
    print(f"replay: {len(records)} tx vs proof {m.invariant} "
          f"(HookHash {m.hook_hash[:8]}…{m.hook_hash[-8:]}) account={acct}")
    for rec in records:
        bucket, detail = classify(rec, m, acct)
        tally[bucket] += 1
        _emit(bucket, detail, rec)

    crit = tally[VIOLATION] + tally[PROOF_VOID]
    print(f"\n  CONSISTENT={tally[CONSISTENT]}  VIOLATION={tally[VIOLATION]}  "
          f"PROOF_VOID={tally[PROOF_VOID]}  UNVERIFIED={tally[UNVERIFIED]}  "
          f"(skipped {tally[SKIP]} non-hook tx)")
    if crit:
        print(f"\n🚨 {crit} CRITICAL finding(s) — proof binding or safety broke.")
        return 2
    if tally[UNVERIFIED]:
        print(f"\n⚠️  {tally[UNVERIFIED]} UNVERIFIED — out of model; not certified (not a breach).")
    print("\n✅ no VIOLATION / PROOF_VOID — every classified tx is consistent with the proof.")
    return 0


async def run_live(manifest_path: str, ws_url: str, account: Optional[str] = None) -> int:
    """Live: subscribe to the bound account and classify each validated tx. Exits non-zero on the
    first CRITICAL finding (VIOLATION / PROOF_VOID). CONSISTENT is quiet; UNVERIFIED is logged."""
    m = load_manifest(manifest_path)
    acct = account or m.hook_account
    if not acct:
        print("ERROR: no account to watch (set manifest.hook_account or pass --account).")
        return 1
    print(f"watching {acct} vs proof {m.invariant} (HookHash {m.hook_hash[:8]}…) on {ws_url}")
    async for rec in ledger.stream_account(ws_url, acct):
        bucket, detail = classify(rec, m, acct)
        _emit(bucket, detail, rec)
        if bucket in CRITICAL:
            print(f"\n🚨 {bucket} — halting watch (exit 2).")
            return 2


def main(argv: list) -> int:
    if not argv:
        print(__doc__)
        return 1
    manifest_path = argv[0]
    rest = argv[1:]
    replay_path = ws_url = account = None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--replay":
            replay_path = rest[i + 1]; i += 2
        elif a == "--ws":
            ws_url = rest[i + 1]; i += 2
        elif a == "--account":
            account = rest[i + 1]; i += 2
        else:
            i += 1
    if replay_path:
        return replay(manifest_path, replay_path, account)
    if ws_url:
        import asyncio
        return asyncio.run(run_live(manifest_path, ws_url, account))
    print("ERROR: pass --replay <fixture.json> (offline) or --ws <url> (live).")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
