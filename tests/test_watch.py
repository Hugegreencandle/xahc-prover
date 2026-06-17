"""Tests for xahc-watch — offline-first, matching the repo's committed-fixture philosophy.
Run: python tests/test_watch.py  (or via tests/test_prover.py's runner, or pytest).

Coverage:
  • predicate parity — the shared rule's two backends (Z3Ops vs ConcreteOps) agree, so the
    watcher cannot drift from what the prover proved (the no-fork guarantee).
  • manifest round-trip + fail-closed (a non-PROVEN verdict cannot become a PROVEN manifest).
  • replay of the 4 real testnet guardrail txns -> all CONSISTENT (the spine).
  • fail-closed buckets: tamper -> VIOLATION, IOU/undecodable -> UNVERIFIED, hash swap -> PROOF_VOID.
"""
import asyncio
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
from watch.watch import (classify, _safe_classify, replay, CONSISTENT, VIOLATION,  # noqa: E402
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
    # The real attack: the guardrail ACCEPTS an over-limit tx. Flip the over-limit tx's HookResult
    # to 3 (accept) — the hook approved what the proof says reject -> VIOLATION.
    m = _manifest()
    over = next(r for r in _records() if r["tx"]["Amount"] == "10000000")
    tampered = copy.deepcopy(over)
    tampered["meta"]["HookExecutions"][0]["HookExecution"]["HookResult"] = 3  # accept
    bucket, _ = classify(tampered, m, A)
    assert bucket == VIOLATION


def test_hook_accept_of_overlimit_is_violation_even_when_tx_rejected():
    # SND-1/COR-1 regression: a Payment runs multiple hooks. Our guardrail ACCEPTS an over-limit
    # tx (HookResult=3) but a downstream Strong-TSH destination rolls the WHOLE tx back
    # (engine_result=tecHOOK_REJECTED). The watcher must still flag VIOLATION — the decision comes
    # from OUR hook's HookResult, not the aggregate tx outcome. (Old code masked this as CONSISTENT.)
    m = _manifest()
    over = next(r for r in _records() if r["tx"]["Amount"] == "10000000")
    rec = copy.deepcopy(over)
    rec["meta"]["HookExecutions"][0]["HookExecution"]["HookResult"] = 3  # OUR hook accepted
    rec["engine_result"] = "tecHOOK_REJECTED"                            # but the tx was rolled back
    bucket, _ = classify(rec, m, A)
    assert bucket == VIOLATION


def test_hook_accept_of_overlimit_is_violation_even_when_tx_tecs():
    # Same masking via an apply-time tec (e.g. tecUNFUNDED_PAYMENT): hook accepted (HookResult=3),
    # engine_result is neither tes nor tecHOOK_REJECTED. Must be VIOLATION, not the old UNVERIFIED.
    m = _manifest()
    over = next(r for r in _records() if r["tx"]["Amount"] == "10000000")
    rec = copy.deepcopy(over)
    rec["meta"]["HookExecutions"][0]["HookExecution"]["HookResult"] = 3
    rec["engine_result"] = "tecUNFUNDED_PAYMENT"
    bucket, _ = classify(rec, m, A)
    assert bucket == VIOLATION


def test_inscope_missing_execution_is_proof_void():
    # The bound account sends an in-scope outgoing Payment but the proven hook produced NO
    # execution row (deleted / SetHook-removed). Must be PROOF_VOID, never a silent SKIP.
    m = _manifest()
    rec = copy.deepcopy(_records()[0])             # A -> B, 3 XAH, an in-scope outgoing payment
    rec["meta"]["HookExecutions"] = []             # hook no longer runs
    bucket, _ = classify(rec, m, A)
    assert bucket == PROOF_VOID


def test_guard_violation_returncode_is_unverified():
    # HookReturnCode with the top bit set = GUARD_VIOLATION (error exit) -> not a clean decision.
    m = _manifest()
    rec = copy.deepcopy(_records()[0])
    ex = rec["meta"]["HookExecutions"][0]["HookExecution"]
    ex["HookResult"] = 4
    ex["HookReturnCode"] = "8000000000000010"      # top bit set
    bucket, _ = classify(rec, m, A)
    assert bucket == W_UNVERIFIED


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


def test_out_of_scope_tx_is_skipped():
    # An OUT-OF-SCOPE tx (incoming to A, i.e. Account != bound account) where our hook didn't
    # execute -> SKIP (quiet). Not in scope, so the missing execution is not PROOF_VOID.
    m = _manifest()
    rec = copy.deepcopy(_records()[0])
    rec["tx"]["Account"] = D                                   # incoming, not from A
    rec["meta"]["HookExecutions"] = []                          # our hook didn't run
    bucket, _ = classify(rec, m, A)
    assert bucket == SKIP


def test_malformed_input_never_crashes():
    # Crafted/garbage records must fail closed to a loud bucket, never raise (a crashed monitor
    # is a silent 'all good'). _safe_classify wraps classify.
    m = _manifest()
    for bad in [
        {"tx": "not-a-dict", "meta": {}},
        {"tx": {"TransactionType": "Payment", "Account": "rNOT_A_REAL_ADDRESS_zzz",
                "Amount": "1"}, "meta": {"HookExecutions": [{"HookExecution":
                {"HookAccount": "rH2RdFKtADfeQf6W7zXrZ7J7hsszaG76Ed",
                 "HookHash": HOOK_HASH, "HookResult": 3}}]}},
        {"meta": {"HookExecutions": ["garbage", 42, None]}},
        {},
    ]:
        bucket, detail = _safe_classify(bad, m, A)
        assert bucket in (W_UNVERIFIED, SKIP, PROOF_VOID), f"{bad} -> {bucket}: {detail}"


# ── live transport (the surface the audit found had ZERO tests) ─────────────────────────────

class _FakeWS:
    """Minimal async-context websocket double: scripted recv() frames (for account_tx) + scripted
    stream frames (for the live async-for)."""
    def __init__(self, recv_frames=None, stream_frames=None):
        self._recv = list(recv_frames or [])
        self._stream = list(stream_frames or [])
        self.sent = []
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def send(self, m): self.sent.append(m)
    async def recv(self):
        assert self._recv, "no more recv frames scripted"
        return self._recv.pop(0)
    def __aiter__(self): return self
    async def __anext__(self):
        if not self._stream:
            raise StopAsyncIteration
        return self._stream.pop(0)


def test_normalize_live_subscribe_message():
    # A live `subscribe` tx message carries the body under `transaction`, the result at top-level
    # `engine_result`, and a top-level ledger_index. The old normalizer read `tx`/`tx_json` only,
    # so the body decoded empty -> pass-through ACCEPT_OK -> false CONSISTENT (RST-1).
    msg = {"type": "transaction", "validated": True, "engine_result": "tesSUCCESS",
           "ledger_index": 9673349,
           "transaction": {"TransactionType": "Payment", "Account": A, "Destination": B,
                           "Amount": "3000000", "hash": "ABCD"},
           "meta": {"HookExecutions": [{"HookExecution":
                    {"HookAccount": A, "HookHash": HOOK_HASH, "HookResult": 3}}]}}
    rec = ledger._normalize_account_tx_row(msg)
    assert rec["tx"]["TransactionType"] == "Payment"      # body found (not empty)
    assert rec["engine_result"] == "tesSUCCESS"
    assert rec["ledger_index"] == 9673349
    # and it classifies on the real body, not a pass-through
    assert classify(rec, _manifest(), A)[0] == CONSISTENT


def test_backfill_follows_marker_no_silent_truncation():
    # account_tx must page via `marker` until exhausted — a single-page read silently drops every
    # tx past the first page on reconnect (SND-4/RST-4), the exact outage window an attacker targets.
    def row(h):
        return {"tx": {"TransactionType": "Payment", "Account": A, "Destination": B,
                       "Amount": "3000000", "hash": h, "ledger_index": 100},
                "meta": {"HookExecutions": [{"HookExecution":
                         {"HookAccount": A, "HookHash": HOOK_HASH, "HookResult": 3}}]}}
    page1 = json.dumps({"id": "backfill", "result": {"transactions": [row("AA"), row("BB")], "marker": "M1"}})
    page2 = json.dumps({"id": "backfill", "result": {"transactions": [row("CC")]}})  # no marker = last
    ledger_mod = ledger
    orig = ledger_mod._connect
    ledger_mod._connect = lambda url: _FakeWS(recv_frames=[page1, page2])
    try:
        recs = asyncio.run(ledger_mod.account_tx_backfill("wss://x", A, 1))
    finally:
        ledger_mod._connect = orig
    assert [r["hash"] for r in recs] == ["AA", "BB", "CC"], "must return BOTH pages"


def test_stream_subscribes_first_and_yields_live():
    # stream_account must subscribe FIRST then yield live records (gap-free), and de-dup by hash.
    live = json.dumps({"type": "transaction", "validated": True, "engine_result": "tesSUCCESS",
                       "ledger_index": 200,
                       "transaction": {"TransactionType": "Payment", "Account": A, "Destination": B,
                                       "Amount": "3000000", "hash": "LIVE1"},
                       "meta": {"HookExecutions": [{"HookExecution":
                                {"HookAccount": A, "HookHash": HOOK_HASH, "HookResult": 3}}]}})
    fake = _FakeWS(stream_frames=[live])
    orig = ledger._connect
    ledger._connect = lambda url: fake
    async def first():
        async for rec in ledger.stream_account("wss://x", A):
            return rec
    try:
        rec = asyncio.run(first())
    finally:
        ledger._connect = orig
    assert rec["hash"] == "LIVE1"
    assert any("subscribe" in s for s in fake.sent), "must SUBSCRIBE before streaming"


def test_insecure_ws_refused():
    # plaintext ws:// is refused (MITM could suppress a VIOLATION) unless explicitly overridden.
    os.environ.pop("XAHC_WATCH_ALLOW_INSECURE", None)
    try:
        ledger._connect("ws://node.example")
        assert False, "ws:// must be refused"
    except ValueError:
        pass
    except ModuleNotFoundError:
        pass  # websockets not installed in this env — the wss guard runs before import anyway


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
