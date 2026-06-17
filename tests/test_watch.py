"""Tests for xahc-watch — offline-first, matching the repo's committed-fixture philosophy.
Run: python tests/test_watch.py  (or via tests/test_prover.py's runner, or pytest).

Coverage:
  • predicate parity — the shared rule's two backends (Z3Ops vs ConcreteOps) agree, so the
    watcher cannot drift from what the prover proved (the no-fork guarantee).
  • manifest round-trip + fail-closed (a non-PROVEN verdict cannot become a PROVEN manifest).
  • replay of the 4 real testnet guardrail txns -> all CONSISTENT (the spine).
  • fail-closed buckets: tamper -> VIOLATION, IOU/undecodable -> UNVERIFIED, hash swap -> PROOF_VOID.
"""
import copy
import json
import os
import sys
import tempfile

import z3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from watch import ledger                                                       # noqa: E402
from watch.predicates import (Z3Ops, ConcreteOps, decode_drops, over_limit,    # noqa: E402
                              dest_not_allowed, guardrail_expected,
                              ACCEPT_OK, SHOULD_REJECT, UNVERIFIED)
from watch.manifest import (ProofManifest, build_manifest, write_manifest,     # noqa: E402
                            load_manifest, hook_hash_of)
from watch.watch import (classify, replay, CONSISTENT, VIOLATION,              # noqa: E402
                         PROOF_VOID, UNVERIFIED as W_UNVERIFIED, SKIP)

H = os.path.join(ROOT, "hooks")
FIX = os.path.join(ROOT, "tests", "fixtures", "watch", "guardrail_testnet.json")
WASM = os.path.join(H, "agent_guardrail.wasm")
HOOK_HASH = "531BD1D72857E9089F8F1C06B1F43E68109BDEB957F952C5348F8A6E675BB20C"

A = "rH2RdFKtADfeQf6W7zXrZ7J7hsszaG76Ed"
B = "rGkfQn5bxTqKnKAJ3pc5NX4GRHEgeuDdbG"
D = "rfWNuoWaFuNNz7BsnX6fgb1cubLpbgXiqy"
B_HEX = ledger.account_id(B).hex().upper()


def _manifest(params=None):
    return ProofManifest(
        invariant="guardrail", verdict="PROVEN [spend-limit, dst-lock]", exit_code=0,
        hook_hash=HOOK_HASH, wasm_sha256="x",
        params=params if params is not None else {"LIM": 5000000, "DST": B_HEX},
        hook_account=A, network_id=21338)


# ── predicate parity: the two backends compute the IDENTICAL rule (no fork) ──────────────────

def _z3_over_limit(amt_bytes, lim):
    amt8 = [z3.BitVecVal(b, 8) for b in amt_bytes]
    drops = decode_drops(amt8, Z3Ops)
    return z3.is_true(z3.simplify(over_limit(drops, z3.BitVecVal(lim, 64), Z3Ops)))


def _concrete_over_limit(amt_bytes, lim):
    return over_limit(decode_drops(list(amt_bytes), ConcreteOps), lim, ConcreteOps)


def test_predicate_parity_spend_limit():
    lim = 5_000_000
    samples = [0, 1, 4_999_999, 5_000_000, 5_000_001, 10_000_000, (1 << 50)]
    for drops in samples:
        amt8 = (drops | ledger.NATIVE_FLAG).to_bytes(8, "big")
        assert _z3_over_limit(amt8, lim) == _concrete_over_limit(amt8, lim), \
            f"backend fork on drops={drops}: symbolic != concrete"
        # and the concrete decode recovers the true drops through the 0x3F mask
        assert decode_drops(list(amt8), ConcreteOps) == drops


def test_predicate_parity_dst_lock_including_byte19_offbyone():
    allowed = list(ledger.account_id(B))
    # exact match -> no mismatch; differ only in the LAST byte (the classic off-by-one) -> mismatch
    same = list(allowed)
    off19 = list(allowed); off19[19] ^= 0x01
    for dest in (same, off19):
        dz = [z3.BitVecVal(b, 8) for b in dest]
        az = [z3.BitVecVal(b, 8) for b in allowed]
        z = z3.is_true(z3.simplify(dest_not_allowed(dz, az, Z3Ops)))
        c = dest_not_allowed(dest, allowed, ConcreteOps)
        assert z == c
    assert dest_not_allowed(same, allowed, ConcreteOps) is False
    assert dest_not_allowed(off19, allowed, ConcreteOps) is True


def test_guardrail_expected_buckets():
    p = {"LIM": 5000000, "DST": ledger.account_id(B)}
    acc = ledger.account_id(A)
    def f(amount8, dest):
        return {"tx_type": 0, "account": acc, "hook_account": acc,
                "amount8": amount8, "destination": dest}
    under = (3000000 | ledger.NATIVE_FLAG).to_bytes(8, "big")
    over = (10000000 | ledger.NATIVE_FLAG).to_bytes(8, "big")
    assert guardrail_expected(f(under, ledger.account_id(B)), p) == ACCEPT_OK
    assert guardrail_expected(f(over, ledger.account_id(B)), p) == SHOULD_REJECT
    assert guardrail_expected(f(under, ledger.account_id(D)), p) == SHOULD_REJECT  # dst-lock
    assert guardrail_expected(f(None, ledger.account_id(B)), p) == UNVERIFIED      # IOU/undecodable
    # incoming (account != hook_account) and non-payment are pass-through accepts
    assert guardrail_expected({"tx_type": 0, "account": ledger.account_id(D),
                               "hook_account": acc, "amount8": over,
                               "destination": ledger.account_id(B)}, p) == ACCEPT_OK


# ── manifest round-trip + fail-closed ───────────────────────────────────────────────────────

def test_manifest_round_trip():
    wasm = open(WASM, "rb").read()
    m = build_manifest(wasm=wasm, invariant="guardrail", verdict="PROVEN", exit_code=0,
                       params={"LIM": 5000000, "DST": B_HEX}, network_id=21338)
    assert m.hook_hash == HOOK_HASH
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "g.proof.json")
        write_manifest(m, p)
        back = load_manifest(p)
    assert back.hook_hash == m.hook_hash
    assert back.params["LIM"] == 5000000
    assert back.params["DST"] == B_HEX
    assert back.invariant == "guardrail"


def test_non_proven_cannot_write_proven_manifest():
    wasm = open(WASM, "rb").read()
    m = build_manifest(wasm=wasm, invariant="guardrail", verdict="COUNTEREXAMPLE",
                       exit_code=2, params={"LIM": 5000000})
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "bad.proof.json")
        try:
            write_manifest(m, p)
            assert False, "write_manifest must refuse a non-PROVEN verdict"
        except ValueError:
            pass
        assert not os.path.exists(p), "no manifest file may be written for a non-PROVEN verdict"


# ── replay the real testnet fixture: every classified tx is CONSISTENT (the spine) ──────────

def _records():
    with open(FIX) as f:
        return json.load(f)["transactions"]


def test_replay_testnet_all_consistent():
    m = _manifest()
    for rec in _records():
        bucket, detail = classify(rec, m, A)
        assert bucket == CONSISTENT, f"{rec['hash'][:8]}: expected CONSISTENT, got {bucket} ({detail})"


def test_replay_cli_exit_zero():
    m = _manifest()
    with tempfile.TemporaryDirectory() as d:
        mp = os.path.join(d, "g.proof.json")
        write_manifest(m, mp)
        assert replay(mp, FIX, A) == 0


# ── fail-closed buckets ─────────────────────────────────────────────────────────────────────

def test_tampered_accept_is_violation():
    # Flip the over-limit tx (1b) to tesSUCCESS: the hook "accepted" what the proof says reject.
    m = _manifest()
    recs = _records()
    over = next(r for r in recs if r["tx"]["Amount"] == "10000000")
    tampered = copy.deepcopy(over)
    tampered["engine_result"] = "tesSUCCESS"
    bucket, _ = classify(tampered, m, A)
    assert bucket == VIOLATION


def test_iou_amount_is_unverified_not_consistent():
    # An IOU amount is out of the native model -> UNVERIFIED, never silently CONSISTENT.
    m = _manifest()
    rec = copy.deepcopy(_records()[0])
    rec["tx"]["Amount"] = {"currency": "USD", "value": "1", "issuer": B}
    bucket, _ = classify(rec, m, A)
    assert bucket == W_UNVERIFIED


def test_changed_hash_is_proof_void():
    # A SetHook swapped the bytecode: deployed HookHash != proven -> PROOF_VOID (proof voided).
    m = _manifest()
    rec = copy.deepcopy(_records()[0])
    rec["meta"]["HookExecutions"][0]["HookExecution"]["HookHash"] = "00" * 32
    bucket, _ = classify(rec, m, A)
    assert bucket == PROOF_VOID


def test_other_hook_tx_is_skipped():
    # A tx where our watched hook did not execute (different HookAccount) -> SKIP (quiet),
    # never classified as CONSISTENT.
    m = _manifest()
    rec = copy.deepcopy(_records()[0])
    rec["meta"]["HookExecutions"][0]["HookExecution"]["HookAccount"] = D
    bucket, _ = classify(rec, m, A)
    assert bucket == SKIP


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
